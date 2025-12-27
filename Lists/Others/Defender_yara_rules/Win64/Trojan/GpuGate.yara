rule Trojan_Win64_GpuGate_SG_2147957538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GpuGate.SG!MSR"
        threat_id = "2147957538"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GpuGate"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "__kernel void stream_decrypt(" ascii //weight: 1
        $x_1_2 = "uint x = seed + i * 1664525 + 1013904223" ascii //weight: 1
        $x_1_3 = "uchar k = (x >> 8) & 0xFF" ascii //weight: 1
        $x_1_4 = "dst[i] = (src[i] - k) & 0xFF" ascii //weight: 1
        $x_1_5 = "OpenCL.dll" ascii //weight: 1
        $x_1_6 = "res.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

