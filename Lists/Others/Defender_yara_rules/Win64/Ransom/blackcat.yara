rule Ransom_Win64_blackcat_DA_2147916894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/blackcat.DA!MTB"
        threat_id = "2147916894"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "blackcat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "files on your system was ENCRYPTED" ascii //weight: 20
        $x_1_2 = "blackcat" ascii //weight: 1
        $x_1_3 = {52 00 45 00 43 00 4f 00 56 00 45 00 52 00 2d 00 [0-15] 2d 00 46 00 49 00 4c 00 45 00 53 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 45 43 4f 56 45 52 2d [0-15] 2d 46 49 4c 45 53 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = "vssadmin.exe Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_6 = "torproject.org" ascii //weight: 1
        $x_1_7 = "Killing processes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

