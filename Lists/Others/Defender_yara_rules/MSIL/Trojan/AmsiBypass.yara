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

