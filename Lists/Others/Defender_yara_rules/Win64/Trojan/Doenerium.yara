rule Trojan_Win64_Doenerium_RSD_2147892613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doenerium.RSD!MTB"
        threat_id = "2147892613"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doenerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TRY_TO_DECRYPT_ME_XD" ascii //weight: 1
        $x_1_2 = "Base64Decode" ascii //weight: 1
        $x_1_3 = "Inject" ascii //weight: 1
        $x_1_4 = "ScreenShot" ascii //weight: 1
        $x_5_5 = "online-bilets.net/stealer" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doenerium_EC_2147907132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doenerium.EC!MTB"
        threat_id = "2147907132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doenerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_7_1 = "win32decrypt.pdb" ascii //weight: 7
        $x_7_2 = "maximumpswd.pdb" ascii //weight: 7
        $x_10_3 = {49 8b 3f 49 8b f4 48 2b f1 48 c1 fe 03 8b ce 48 8b 04 ca 48 c1 e8 3f 83 f0 01 89 45 d0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_7_*))) or
            (all of ($x*))
        )
}

