rule Ransom_Win64_Osiris_YBG_2147961275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Osiris.YBG!MTB"
        threat_id = "2147961275"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Osiris"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 0f 47 4d ef 48 8d 15 fe 18 02 00 ff 15 ?? ?? ?? ?? 48 85 c0 0f 85 ?? ?? ?? ?? 48 8d 4d ef 48 83 7d 07 07 48 0f 47 4d ef 48 8d 15 f2 18 02 00 ff 15 44 0a 02 00 48 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "Shadow Copies: found snapshot" wide //weight: 1
        $x_1_3 = "Encryption: make keys" wide //weight: 1
        $x_1_4 = " Shadow Copies: deleted snapshot" wide //weight: 1
        $x_1_5 = "%s\\%s-MESSAGE.txt" wide //weight: 1
        $x_1_6 = "Encryption: found drive" wide //weight: 1
        $x_1_7 = "Osiris" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

