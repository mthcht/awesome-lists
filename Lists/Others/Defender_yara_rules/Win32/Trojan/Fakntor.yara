rule Trojan_Win32_Fakntor_B_2147743216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakntor.B!MSR"
        threat_id = "2147743216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakntor"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe %s ,NvSmartMaxUseDynamicDeviceGrids" ascii //weight: 1
        $x_1_2 = "%sEx.exe" ascii //weight: 1
        $x_1_3 = "945F4106-C691-4921-ACAB-E58C50C5F150" wide //weight: 1
        $x_1_4 = "CF08C3F3-2CA3-4215-8CB3-4CDBD3030EC4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Fakntor_C_2147743217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakntor.C!MSR"
        threat_id = "2147743217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakntor"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\windows\\system32\\NarratorMain.exe" ascii //weight: 1
        $x_1_2 = {43 3a 5c 6d 79 57 6f 72 6b 5c 76 63 5c 4e 61 72 72 61 74 6f 72 5f 77 69 6e 64 6f 77 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4e 61 72 72 61 74 6f 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

