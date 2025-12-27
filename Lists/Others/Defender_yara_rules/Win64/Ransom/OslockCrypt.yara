rule Ransom_Win64_OslockCrypt_PC_2147953316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/OslockCrypt.PC!MTB"
        threat_id = "2147953316"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "OslockCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmindeleteshadows/all/quiet" ascii //weight: 1
        $x_2_2 = "KCVY OSLOCK V3.0 - YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

