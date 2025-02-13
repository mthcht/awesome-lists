rule Backdoor_MacOS_Nukesped_A_2147745471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Nukesped.A!MTB"
        threat_id = "2147745471"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Nukesped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wb-bot.org/certpkg.php" ascii //weight: 2
        $x_1_2 = "/var/pkglibcert" ascii //weight: 1
        $x_1_3 = "name=\"upload\"; filename=\"temp.gif\"" ascii //weight: 1
        $x_1_4 = {45 31 ed 89 d9 83 e1 0f 46 32 2c 21 48 63 70 04 48 39 f3 7d 2b 8b 08 83 f9 01 77 07 48 83 78 10 18 74 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

