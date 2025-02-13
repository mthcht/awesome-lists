rule Trojan_MSIL_plugx_2147842175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/plugx.psyE!MTB"
        threat_id = "2147842175"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "plugx"
        severity = "Critical"
        info = "psyE: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {73 12 00 00 06 0a 06 28 1c 00 00 0a 7d 07 00 00 04 06 02 7d 09 00 00 04 06 03 7d 08 00 00 04 06 15 7d 06 00 00 04 06 7c 07 00 00 04 12 00 28 03 00 00 2b 06 7c 07 00 00 04 28 1e 00 00 0a 2a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_plugx_2147844413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/plugx.psyH!MTB"
        threat_id = "2147844413"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "plugx"
        severity = "Critical"
        info = "psyH: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {14 fe 06 02 00 00 06 73 02 00 00 0a 28 03 00 00 06 7e 01 00 00 04 2c 0c 7e 01 00 00 04 14 14 6f 03 00 00 0a 2a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_plugx_2147844414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/plugx.psyI!MTB"
        threat_id = "2147844414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "plugx"
        severity = "Critical"
        info = "psyI: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {73 15 00 00 06 0a 06 7e 14 00 00 0a 7d 07 00 00 04 06 fe 06 16 00 00 06 73 15 00 00 0a 73 16 00 00 0a 0b 07 16 6f 17 00 00 0a 07 6f 18 00 00 0a 07 6f 19 00 00 0a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_plugx_2147845839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/plugx.psyJ!MTB"
        threat_id = "2147845839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "plugx"
        severity = "Critical"
        info = "psyJ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {72 01 00 00 70 17 8d 1c 00 00 01 25 16 1f 2d 9d 28 0d 00 00 0a 17 9a 6f 0e 00 00 0a 72 c4 00 00 70 17}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_plugx_2147845840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/plugx.psyK!MTB"
        threat_id = "2147845840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "plugx"
        severity = "Critical"
        info = "psyK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {19 2c 0d 72 1d 00 00 70 2b 08 2b 0d 2b 12 2b 17 de 1b 28 06 00 00 06 2b f1 28 01 00 00 2b 2b ec 28 02 00 00 2b 2b e7 0a 2b e6}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

