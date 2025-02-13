rule Ransom_Win32_BabukLockr_PA_2147772027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BabukLockr.PA!MTB"
        threat_id = "2147772027"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BabukLockr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "****BY BABUK LOCKER****" ascii //weight: 1
        $x_1_3 = ".__NIST_K571__" wide //weight: 1
        $x_1_4 = "How To Restore Your Files.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BabukLockr_PB_2147772068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BabukLockr.PB!MTB"
        threat_id = "2147772068"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BabukLockr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {fe c0 32 c1 2c 5a c0 c8 02 02 c1 f6 d8 32 c1 c0 c0 02 02 c1 88 84 ?? ?? ?? ?? ?? 41 81 f9 05 50 00 00 72}  //weight: 3, accuracy: Low
        $x_1_2 = "thqjq2i7omzcxe5z1yim" ascii //weight: 1
        $x_1_3 = "WIOSOSOSOW" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

