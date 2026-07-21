// SPDX-License-Identifier: AGPL-3.0-or-later

use std::arch::x86_64::__cpuid;

const CPUID_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 0x1;
const CPUID_GET_HIGHEST_FUNCTION: u32 = 0x80000000;
const CPUID_FEATURE_HYPERVISOR: u32 = 1 << 31;

const CPUID_HYPERV_SIG: &[u8] = b"Microsoft Hv";
const CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x40000000;
const CPUID_HYPERV_FEATURES: u32 = 0x40000003;
const CPUID_HYPERV_MIN: u32 = 0x40000005;
const CPUID_HYPERV_MAX: u32 = 0x4000ffff;
const CPUID_HYPERV_ISOLATION: u32 = 1 << 22;
const CPUID_HYPERV_CPU_MANAGEMENT: u32 = 1 << 12;
const CPUID_HYPERV_ISOLATION_CONFIG: u32 = 0x4000000C;
const CPUID_HYPERV_ISOLATION_TYPE_MASK: u32 = 0xf;
const CPUID_HYPERV_ISOLATION_TYPE_SNP: u32 = 2;
const CPUID_HYPERV_ISOLATION_TYPE_TDX: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationType {
    Snp,
    Tdx,
}

pub fn get_isolation_type() -> Option<IsolationType> {
    let cpuid = __cpuid(CPUID_PROCESSOR_INFO_AND_FEATURE_BITS);
    if (cpuid.ecx & CPUID_FEATURE_HYPERVISOR) == 0 {
        return None;
    }

    let cpuid = __cpuid(CPUID_GET_HIGHEST_FUNCTION);
    if cpuid.eax < CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS {
        return None;
    }

    let cpuid = __cpuid(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS);
    if cpuid.eax < CPUID_HYPERV_MIN || cpuid.eax > CPUID_HYPERV_MAX {
        return None;
    }

    let mut sig = Vec::with_capacity(12);
    sig.extend_from_slice(&cpuid.ebx.to_le_bytes());
    sig.extend_from_slice(&cpuid.ecx.to_le_bytes());
    sig.extend_from_slice(&cpuid.edx.to_le_bytes());

    if sig != CPUID_HYPERV_SIG {
        return None;
    }

    let cpuid = __cpuid(CPUID_HYPERV_FEATURES);
    let isolated = (cpuid.ebx & CPUID_HYPERV_ISOLATION) != 0;
    let managed = (cpuid.ebx & CPUID_HYPERV_CPU_MANAGEMENT) != 0;

    if !isolated || managed {
        return None;
    }

    let cpuid = __cpuid(CPUID_HYPERV_ISOLATION_CONFIG);
    let isolation_type = cpuid.ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK;

    match isolation_type {
        CPUID_HYPERV_ISOLATION_TYPE_SNP => Some(IsolationType::Snp),
        CPUID_HYPERV_ISOLATION_TYPE_TDX => Some(IsolationType::Tdx),
        _ => None,
    }
}
