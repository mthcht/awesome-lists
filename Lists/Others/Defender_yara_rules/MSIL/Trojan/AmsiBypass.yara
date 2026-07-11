rule Trojan_MSIL_AmsiBypass_NE_2147827660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AmsiBypass.NE!MTB"
        threat_id = "2147827660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AmsiBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 11 04 11 04 07 95 11 04 08 95 58 20 ff 00 00 00 5f 95 61 28 ?? 00 00 0a 9c 11 06 17 58 13 06}  //weight: 1, accuracy: Low
        $x_1_2 = "SELECT * FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_3 = "T0s=" wide //weight: 1
        $x_1_4 = "WVcxemFTNWtiR3c9" wide //weight: 1
        $x_1_5 = "UVcxemFWTmpZVzVDZFdabVpYST0=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AmsiBypass_NB_2147904796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AmsiBypass.NB!MTB"
        threat_id = "2147904796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AmsiBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 8e 69 5d 91 61 d2 9c 11 0d 17 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AmsiBypass_CCHT_2147904999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AmsiBypass.CCHT!MTB"
        threat_id = "2147904999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AmsiBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 11 08 6f ?? 00 00 0a 11 19 91 11 0a 11 19 11 0a 8e 69 5d 91 61 d2 6f ?? 00 00 0a 11 19 17 58 13 19 11 19 6a 11 08 6f ?? 00 00 0a 32 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AmsiBypass_CCHZ_2147910221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AmsiBypass.CCHZ!MTB"
        threat_id = "2147910221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AmsiBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "amsi.dll" ascii //weight: 10
        $x_10_2 = "AmsiScanBuffer" ascii //weight: 10
        $x_10_3 = "YW1zaS5kbGw=" ascii //weight: 10
        $x_10_4 = "QW1zaVNjYW5CdWZmZXI=" ascii //weight: 10
        $x_1_5 = "D84F4C120005F1837DC65C04181F3DA9466B123FC369C359A301BABC12061570" ascii //weight: 1
        $x_1_6 = "Patch Applied" ascii //weight: 1
        $x_1_7 = "The number of processes in the system is less than 40. Exiting the program" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_AmsiBypass_LRB_2147973347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AmsiBypass.LRB!MTB"
        threat_id = "2147973347"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AmsiBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {02 28 17 00 00 0a 0a d0 19 00 00 01 28 18 00 00 0a 28 19 00 00 0a 0b 07 72 01 00 00 70 28 1a 00 00 0a 14 d0 02 00 00 1b 28 18 00 00 0a 28 1b 00 00 0a 0c 72 17 00 00 70 14 18 8d 25 00 00 01 25 16 06 28 1c 00 00 0a a2 25 17 08 a2 28 1d 00 00 0a 17 8d 1a 00 00 01 25 16 07 a2 28 02 00 00 2b 6f 1f 00 00 0a 06 6f 20 00 00 0a}  //weight: 20, accuracy: High
        $x_10_2 = {12 00 28 14 00 00 0a 7d 06 00 00 04 12 00 02 7d 07 00 00 04 12 00 03 7d 08 00 00 04 12 00 04 7d 09 00 00 04 12 00 15 7d 05 00 00 04 12 00 7c 06 00 00 04 12 00 28 01 00 00 2b 12 00 7c 06 00 00 04 28 16 00 00 0a 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

