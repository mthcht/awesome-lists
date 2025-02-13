rule TrojanDownloader_MSIL_LokiBot_EV_2147818326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LokiBot.EV!MTB"
        threat_id = "2147818326"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 02 07 91 6f ?? ?? ?? 0a 07 25 17 59 19 2d 0a 26 16 fe 02 0c 08 2d e7}  //weight: 1, accuracy: Low
        $x_1_2 = {26 12 01 23 00 00 00 00 00 00 35 40 28 1b 00 00 0a 19 2d 06 26 2b 06 0b 2b e7 0a 2b 00 06 28}  //weight: 1, accuracy: High
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LokiBot_EW_2147818604_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LokiBot.EW!MTB"
        threat_id = "2147818604"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GT8ZZ5G48CY4R4FAF4HH7F" wide //weight: 1
        $x_1_2 = "Thesis1" wide //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LokiBot_EX_2147818648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LokiBot.EX!MTB"
        threat_id = "2147818648"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "38F4WP9E4HH858FASCJSB5" wide //weight: 1
        $x_1_2 = "Rostisa" wide //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LokiBot_EY_2147819572_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LokiBot.EY!MTB"
        threat_id = "2147819572"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {12 05 23 00 00 00 00 00 00 33 40 28 ?? ?? ?? 0a 13 04 2b [0-4] 00 00 11 04 28 ?? ?? ?? 0a}  //weight: 10, accuracy: Low
        $x_1_2 = {06 07 02 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e7}  //weight: 1, accuracy: Low
        $x_1_3 = {2b b4 0a 2b b3 02 38 ?? ?? ?? ?? 0b 2b b5 06 2b ba 07 2b b9 02 2b b8 07 2b b7 6f ?? ?? ?? 0a 2b b3}  //weight: 1, accuracy: Low
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_LokiBot_EZ_2147819573_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LokiBot.EZ!MTB"
        threat_id = "2147819573"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 12 04 28 ?? ?? ?? 0a [0-1] 07 08 02 08 91 6f ?? ?? ?? 0a [0-1] de ?? 11 04 2c ?? 09 28 ?? ?? ?? 0a [0-1] dc}  //weight: 10, accuracy: Low
        $x_1_2 = {12 01 23 00 00 00 00 00 00 24 40 28 ?? ?? ?? 0a 0d 2b 02 00 00 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 11 04 2d ed}  //weight: 1, accuracy: Low
        $x_1_3 = {12 01 23 00 00 00 00 00 00 24 40 28 ?? ?? ?? 0a 1d 2d 06 26 2b 06 0b 2b e7 0a 2b 00 06 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_LokiBot_C_2147829376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LokiBot.C!MTB"
        threat_id = "2147829376"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 16 06 8e 69 28}  //weight: 1, accuracy: High
        $x_1_2 = {02 28 06 00 00 06 0a 06 73 ?? 00 00 0a 0b 00 07 20 80 f0 fa 02 6f ?? 00 00 0a 0c de 0b 07 2c 07 07 6f ?? 00 00 0a 00 dc}  //weight: 1, accuracy: Low
        $x_1_3 = "WebRequest" ascii //weight: 1
        $x_1_4 = "GetResponse" ascii //weight: 1
        $x_1_5 = "WebResponse" ascii //weight: 1
        $x_1_6 = "GetResponseStream" ascii //weight: 1
        $x_1_7 = "GetTypes" ascii //weight: 1
        $x_1_8 = "GetMethod" ascii //weight: 1
        $x_1_9 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LokiBot_RDC_2147833132_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LokiBot.RDC!MTB"
        threat_id = "2147833132"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 07 09 07 8e 69 5d 91 02 09 91 61 d2 6f ?? ?? ?? 0a 09 17 58 0d 09 02 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_LokiBot_CCHD_2147901427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/LokiBot.CCHD!MTB"
        threat_id = "2147901427"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 38 ?? 00 00 00 06 28 ?? 00 00 0a 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 07 28 ?? 00 00 0a 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

