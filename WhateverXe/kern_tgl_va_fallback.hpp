// Opt-in Tiger Lake VA userspace page fix.
// The VA driver's type-2 video-processing output lists are cleared while the
// decode/encode capability counts remain. AppleGVA then selects its non-VPHAL
// fallback for post-processing instead of submitting the media-object stream
// that stalls RCS on this driver stack. The patch is applied to the VA driver's
// pages during code-signing page validation, so the on-disk bundle and its
// signature are untouched. Exact page digests and fields are required; the
// physical GPU identity is never spoofed.
#ifndef kern_tgl_va_fallback_hpp
#define kern_tgl_va_fallback_hpp
#include <mach/kern_return.h>
#include <sys/vnode.h>
#include <pexpert/pexpert.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSSerialize.h>
#include <Headers/kern_api.hpp>
#include <Headers/kern_mach.hpp>
#include <Headers/kern_patcher.hpp>
#include "kern_tgl_va_pages.hpp"
#include "kern_xelp_platform.hpp"

namespace TGLVAFallback {
using Validator = void (*)(vnode_t,memory_object_t,memory_object_offset_t,
 const void *,int *,int *,int *);
static Validator orgValidatePage {};
static bool requested {},ready {},probeOnly {};
static uint32_t selectedSites {TGLVAPages::AllSiteMask};
static uint32_t matchedSites {},patchedSites {};
static uint64_t pagesMask {},patches {},matches {},lastValidated {},lastTainted {};
static uint64_t lastNx {},lastOffset {};

// AI 修改: parse the site mask from the raw boot-arg string. PE_parse_boot_argn
// on this kernel folded the numeric value to its first digit, so the selector
// was silently reduced to bit0. Accept both 0x-prefixed hex and decimal.
inline uint32_t parseSiteValue(const char *value) {
 uint32_t mask=0;
 if (value[0]=='0' && (value[1]=='x' || value[1]=='X')) {
  value+=2;
  while (*value) {
   unsigned digit;
   if (*value>='0' && *value<='9')digit=unsigned(*value-'0');
   else if (*value>='a' && *value<='f')digit=unsigned(*value-'a')+10;
   else if (*value>='A' && *value<='F')digit=unsigned(*value-'A')+10;
   else break;
   mask=(mask<<4)|digit;++value;
  }
 } else {
  while (*value>='0' && *value<='9') {
   mask=mask*10+unsigned(*value-'0');++value;
  }
 }
 return mask&TGLVAPages::AllSiteMask;
}

inline uint32_t bootSiteMask() {
 static const char key[]="-wex-tgl-va-sites=";
 const char *args=PE_boot_args();
 if (!args) return TGLVAPages::AllSiteMask;
 for (const char *p=args;*p;++p) {
  if (p!=args && p[-1]!=' ') continue;
  const char *k=key,*q=p;
  while (*k && *q==*k) {++k;++q;}
  if (!*k) return parseSiteValue(q);
 }
 return TGLVAPages::AllSiteMask;
}

inline bool scope(const XELP::Profile &profile) {
 // Exact physical Tiger Lake 9A49 revision 1; a device-id override disables
 // the fallback because the page list belongs to the native VA donor.
 return profile.identity==0x9A498086 && profile.revision==0x1 &&
  !profile.overridden() && XELP::same(profile,XELP::identify(0x9A498086,0x1));
}

static void validatePage(vnode_t vnode,memory_object_t pager,
 memory_object_offset_t offset,const void *data,int *validated,
 int *tainted,int *nx) {
 if (orgValidatePage)
  orgValidatePage(vnode,pager,offset,data,validated,tainted,nx);
 if (!validated || !tainted || !nx) return;
 // Sequoia marks a completed validation with 0xf; tainted and non-executable
 // pages are rejected rather than patched.
 if (*validated!=0xf || *tainted || *nx) return;
 if (!requested) return;
 const int page=TGLVAPages::match(data,4096,uint64_t(offset));
 if (page<0) return;
 const uint32_t pageSites=TGLVAPages::pageSiteMask(unsigned(page));
 const uint32_t selected=pageSites&selectedSites;
 __atomic_fetch_add(&matches,1ULL,__ATOMIC_RELAXED);
 __atomic_store_n(&lastValidated,uint64_t(*validated),__ATOMIC_RELAXED);
 __atomic_store_n(&lastTainted,uint64_t(*tainted),__ATOMIC_RELAXED);
 __atomic_store_n(&lastNx,uint64_t(*nx),__ATOMIC_RELAXED);
 __atomic_store_n(&lastOffset,uint64_t(offset),__ATOMIC_RELAXED);
 __atomic_fetch_or(&matchedSites,pageSites,__ATOMIC_RELAXED);
 // Probe mode records which capability pages are actually validated without
 // changing them; an empty selected mask is also detection-only.
 SYSLOG("igfx","TGL VA page %d offset 0x%llx sites 0x%05x selected 0x%05x %s",
  page,uint64_t(offset),pageSites,selected,probeOnly?"probe":"patch");
 if (probeOnly || !selected) return;
 if (MachInfo::setKernelWriting(true,KernelPatcher::kernelWriteLock)!=KERN_SUCCESS)
  return;
 // Readers may race with the validator; recheck the complete page while the
 // kernel write lock is held before editing it.
 if (TGLVAPages::match(data,4096,uint64_t(offset))==page) {
  const auto cleared=TGLVAPages::applyMasked(const_cast<void *>(data),
   unsigned(page),selectedSites);
  if (cleared) {
   __atomic_fetch_or(&pagesMask,1ULL<<unsigned(page),__ATOMIC_RELEASE);
   __atomic_fetch_or(&patchedSites,selected,__ATOMIC_RELEASE);
   __atomic_fetch_add(&patches,1ULL,__ATOMIC_RELAXED);
  }
 }
 MachInfo::setKernelWriting(false,KernelPatcher::kernelWriteLock);
}

static bool serializeLive(void *,void *,OSSerialize *serializer) {
 // Schema 4 adds the selected/matched/patched site masks and probe state so a
 // subset test can be read back without guessing which pages were touched.
 const uint64_t q[] {4,requested && ready,
  __atomic_load_n(&pagesMask,__ATOMIC_ACQUIRE),
  __atomic_load_n(&patches,__ATOMIC_RELAXED),
  __atomic_load_n(&matches,__ATOMIC_RELAXED),
  __atomic_load_n(&lastValidated,__ATOMIC_RELAXED),
  __atomic_load_n(&lastTainted,__ATOMIC_RELAXED),
  __atomic_load_n(&lastNx,__ATOMIC_RELAXED),
  __atomic_load_n(&lastOffset,__ATOMIC_RELAXED),
  selectedSites,
  __atomic_load_n(&matchedSites,__ATOMIC_RELAXED),
  __atomic_load_n(&patchedSites,__ATOMIC_RELAXED),
  probeOnly ? 1ULL : 0ULL};
 auto data=OSData::withBytes(q,sizeof(q));
 if (!data) return false;
 const bool ok=data->serialize(serializer);
 data->release();
 return ok;
}

inline void prepare(KernelPatcher &patcher,IOPCIDevice *gpu,
 const XELP::Profile &profile,bool optIn) {
 auto root=IORegistryEntry::getRegistryRoot();
 if (!root) return;
 const bool nativeOS=getKernelVersion()==KernelVersion::Sequoia;
 const bool inScope=gpu && nativeOS && scope(profile);
 const bool probe=inScope && checkKernelArgument("-wex-tgl-va-probe");
 selectedSites=bootSiteMask();
 // Probe mode installs the observation hook but never edits a page. Enabling
 // both switches keeps probe authoritative so a test run cannot patch silently.
 requested=inScope && (optIn || probe);
 probeOnly=requested && probe;
 root->setProperty("WEXTGLVAFallbackRequested",requested);
 root->setProperty("WEXTGLVAFallbackProbe",probeOnly);
 root->setProperty("WEXTGLVAFallbackSites",selectedSites);
 SYSLOG("igfx","TGL VA filter requested=%d probe=%d sites=0x%05x",
  requested,probeOnly,selectedSites);
 if (requested) {
  KernelPatcher::RouteRequest route("_cs_validate_page",validatePage,
   orgValidatePage);
  ready=patcher.routeMultipleLong(KernelPatcher::KernelID,&route,1);
  patcher.clearError();
 }
 root->setProperty("WEXTGLVAFallbackReady",requested && ready);
 if (auto live=OSSerializer::forTarget(nullptr,serializeLive)) {
  root->setProperty("WEXTGLVAFallbackLive",live);
  live->release();
 }
}
}
#endif
