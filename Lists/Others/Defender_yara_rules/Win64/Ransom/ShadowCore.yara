rule Ransom_Win64_ShadowCore_AR_2147962291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ShadowCore.AR!AMTB"
        threat_id = "2147962291"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ShadowCore"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "SHADOW CORE RANSOMWARE" ascii //weight: 1
        $x_1_3 = "After deadline: PERMANENT DATA LOSS" ascii //weight: 1
        $x_1_4 = "Email transaction ID to: shadow@tutanota.com" ascii //weight: 1
        $x_1_5 = "\\!!!SHADOW_READ_ME!!!.txt" ascii //weight: 1
        $x_1_6 = ".SHADOWLOCKED" ascii //weight: 1
        $x_1_7 = "Your files have been encrypted by SHADOW CORE ransomware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

