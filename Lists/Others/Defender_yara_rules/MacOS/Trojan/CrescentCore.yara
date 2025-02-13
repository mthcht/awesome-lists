rule Trojan_MacOS_CrescentCore_A_2147746264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CrescentCore.A!MTB"
        threat_id = "2147746264"
        type = "Trojan"
        platform = "MacOS: "
        family = "CrescentCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com.l.r.l.m" ascii //weight: 10
        $x_1_2 = "/Desktop/WaningCrescent/WaningCrescent/" ascii //weight: 1
        $x_1_3 = "ioreg -l | grep -e Manufacturer" ascii //weight: 1
        $x_1_4 = "rm -rf /tmp/Updater.zip" ascii //weight: 1
        $x_1_5 = "DownloadOfferObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_CrescentCore_B_2147787748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/CrescentCore.B!MTB"
        threat_id = "2147787748"
        type = "Trojan"
        platform = "MacOS: "
        family = "CrescentCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "com.lights.Oblivion" ascii //weight: 2
        $x_1_2 = "5UA7HW48Y71" ascii //weight: 1
        $x_1_3 = "ioreg -l | grep -e Manufacturer" ascii //weight: 1
        $x_1_4 = {55 70 64 61 74 65 72 [0-2] 4e 65 74 77 6f 72 6b 44 6f 77 6e 6c 6f 61 64 65 72}  //weight: 1, accuracy: Low
        $x_1_5 = "DownloadOfferObject" ascii //weight: 1
        $x_2_6 = {48 89 43 50 48 89 53 58 49 8d b6 03 00 3a 00 48 bf 49 67 6b 54 44 67 77 49 e8 ba 0e 00 00 48 89 43 60 48 89 53 68 48 bf 4e 51 34 54 41 67 6b 3d 4c 89 fe e8 a0 0e 00 00 48 89 43 70 48 89 53 78 48 bf 49 78 4d 41 46 77 51 3d 4c 89 fe e8 86 0e 00 00 48 89 83 80 00 00 00 48 89 93 88 00 00 00 49 8d b6 02 26 14 17 48 bf 4d 44 41 6a 45 77 34 57 e8 62 0e 00 00 48 89 83 90 00 00 00 48 89 93 98 00 00 00 48 bf 4f 41 41 50 42 51 51 5a 4c 89 fe}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

