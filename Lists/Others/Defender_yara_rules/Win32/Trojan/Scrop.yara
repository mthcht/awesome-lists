rule Trojan_Win32_Scrop_BM_2147771230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scrop.BM!MSR"
        threat_id = "2147771230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scrop"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUID.bin" ascii //weight: 1
        $x_1_2 = "PstCMD_SC" ascii //weight: 1
        $x_1_3 = "judystevenson.info/vcapicv/vchivmqecv" ascii //weight: 1
        $x_1_4 = "winmgmts:\\\\localhost\\root\\SecurityCenter2" ascii //weight: 1
        $x_1_5 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SecProcessingWindowsSystem.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

