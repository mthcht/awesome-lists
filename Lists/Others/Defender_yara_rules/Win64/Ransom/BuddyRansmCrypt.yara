rule Ransom_Win64_BuddyRansmCrypt_PA_2147839368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BuddyRansmCrypt.PA!MTB"
        threat_id = "2147839368"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BuddyRansmCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".buddyransome" ascii //weight: 1
        $x_1_2 = "HOW_TO_RECOVERY_FILES.txt" ascii //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

