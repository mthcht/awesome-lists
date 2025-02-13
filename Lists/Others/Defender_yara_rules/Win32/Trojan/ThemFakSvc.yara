rule Trojan_Win32_ThemFakSvc_SP_2147753484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ThemFakSvc.SP!MSR"
        threat_id = "2147753484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ThemFakSvc"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\TlsHelperXBundler\\Release\\XBundlerTlsHelper.pdb" ascii //weight: 1
        $x_1_2 = "Windows Update Assistant" wide //weight: 1
        $x_1_3 = "svchost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

