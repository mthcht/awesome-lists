rule Trojan_Win32_Brontok_A_2147707237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brontok.A"
        threat_id = "2147707237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brontok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ISI SEKARANG" ascii //weight: 1
        $x_1_2 = "APA KABAR SEMUANYA LAM KENAL" ascii //weight: 1
        $x_1_3 = "Dengan hormat kepada bapak/ibu/saudara yang saya hormati di komputer ini." ascii //weight: 1
        $x_5_4 = {6a 00 c7 45 e0 04 00 02 80 c7 45 d8 0a 00 00 00 89 75 b0 c7 45 a8 08 40 00 00 ff 15 94 11 40 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Brontok_AMMB_2147904395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brontok.AMMB!MTB"
        threat_id = "2147904395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brontok"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ubtlljmmAPgAPjnA" wide //weight: 1
        $x_1_2 = "dpnqvufsobnf" wide //weight: 1
        $x_1_3 = {53 01 52 00 53 00 62 00 63 00 54 00 55 00 64 00 65 00 4e 00 56 00 57 00 66 00 67 00 4e 00 58 00 59 00 62 00 63 00 4e 00 5a 00 52 00 62 00 63 00 64 00 52 00 52 00 53 00 65 00 66 00 67 00 68 00 7e 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

