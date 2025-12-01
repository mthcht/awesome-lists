rule Trojan_MSIL_PSWStealer_XE_2147823558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.XE!MTB"
        threat_id = "2147823558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_2 = "obj\\Debug\\fudloader.pdb" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "glybzjepapkisf" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
        $x_1_8 = "set_PasswordValue" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PSWStealer_ARA_2147836267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.ARA!MTB"
        threat_id = "2147836267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\VertexSpooferFullSRC.pdb" ascii //weight: 2
        $x_2_2 = "://cdn.discordapp.com/attachments/" wide //weight: 2
        $x_2_3 = "/perm_spoofer.zip" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PSWStealer_MBFZ_2147850548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.MBFZ!MTB"
        threat_id = "2147850548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2b1df0e1ab8b" ascii //weight: 1
        $x_1_2 = "quanlykho.Properties" ascii //weight: 1
        $x_1_3 = "dangnhap" ascii //weight: 1
        $x_1_4 = "formThemnhap" ascii //weight: 1
        $x_1_5 = "frmHuongDan" ascii //weight: 1
        $x_1_6 = "ketnoi" ascii //weight: 1
        $x_1_7 = "Xuathang" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PSWStealer_AWA_2147919064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.AWA!MTB"
        threat_id = "2147919064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "directoryTempForCopyLoginDataFiles" ascii //weight: 2
        $x_2_2 = "\\Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_3 = "\\K-Melon\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_4 = "\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 2
        $x_2_5 = "curl --ssl-no-revoke -X POST \"https://api.telegram.org/bot" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PSWStealer_CZI_2147953331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.CZI!MTB"
        threat_id = "2147953331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 79 00 00 0a 6f 13 00 00 0a 25 72 46 0d 00 70 28 11 00 00 0a 0b 72 68 0d 00 70 28 11 00 00 0a 28 60 00 00 0a 6f 61 00 00 0a 6f 62 00 00 0a 07 17 28 18 00 00 0a 07 1c 28 7a 00 00 0a 07 28 11 00 00 06 06 6f 44 00 00 0a 2d af}  //weight: 2, accuracy: High
        $x_2_2 = {72 02 0d 00 70 02 72 08 0d 00 70 28 15 00 00 0a 0a 03 06 17 28 18 00 00 0a de 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PSWStealer_CSI_2147958536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PSWStealer.CSI!MTB"
        threat_id = "2147958536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 00 28 01 00 00 0a 7d 24 00 00 04 12 00 03 7d 27 00 00 04 12 00 04 7d 25 00 00 04 12 00 05 7d 26 00 00 04 12 00 15 7d 23 00 00 04 12 00 7c 24 00 00 04 12 00 28 07 00 00 2b 12 00 7c 24 00 00 04 28 03 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_2 = {28 0a 00 00 0a 28 0b 00 00 0a 0a 16 0b 38 8b 00 00 00 06 07 9a 0c 08 28 0c 00 00 0a 0d 28 0a 00 00 0a 09 72 39 00 00 70 28 0d 00 00 0a 28 0e 00 00 0a 13 04 11 04 28 08 00 00 0a 2c 5c 02 11 04 6f 09 00 00 0a 02 08 6f 09 00 00 0a 18 8d 08 00 00 01 25 16 72 3d 00 00 70 a2 25 17 72 47 00 00 70 a2 13 05 16 13 06 2b 28 11 05 11 06 9a 13 07 08 11 07 28 0e 00 00 0a 13 08 11 08 28 08 00 00 0a 2c 08 02 11 08 6f 09 00 00 0a 11 06 17 58 13 06 11 06 11 05 8e 69 32 d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

