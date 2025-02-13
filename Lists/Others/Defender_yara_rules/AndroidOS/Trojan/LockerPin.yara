rule Trojan_AndroidOS_LockerPin_A_2147816687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockerPin.A!MTB"
        threat_id = "2147816687"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockerPin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 80 11 00 62 08 ?? ?? 6e 10 ?? ?? 08 00 0c 08 07 84 07 18 01 39 07 1a 01 3b 48 0a 0a 0b 07 4b 01 3c 07 4d 21 dd b4 dc 48 0b 0b 0c b7 ba 8e aa 8d aa 4f 0a 08 09 d8 03 03 01 ?? ?? 07 38 07 59 6e 20 ?? ?? 98 00 0a 08 01 86 07 48 07 59 12 0a 01 6b}  //weight: 2, accuracy: Low
        $x_1_2 = "com/bug/ceshi/pin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

