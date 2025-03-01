rule TrojanDownloader_MSIL_CobaltStrike_ACS_2147843995_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CobaltStrike.ACS!MTB"
        threat_id = "2147843995"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 59 0c 17 0d 2b 2d 17 13 04 2b 1f 02 11 04 09 6f 16 00 00 0a 13 05 06 12 05 28 17 00 00 0a 6f 18 00 00 0a 26 11 04 17 58 13 04 11 04 07 31 dc 09 17 58 0d 09 08 31 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CobaltStrike_AV_2147917012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CobaltStrike.AV!MTB"
        threat_id = "2147917012"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "134.122.176.156" wide //weight: 2
        $x_1_2 = "ByPassbbb" wide //weight: 1
        $x_1_3 = "l8brmJSA79tc6z01ugButg==" wide //weight: 1
        $x_2_4 = "COM_Surrogate.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CobaltStrike_KSAY_2147920339_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CobaltStrike.KSAY!MTB"
        threat_id = "2147920339"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NLc0MDg9zP6VTvRMbffF0O23WgXbBZBl3PO9/14+ABQ=" ascii //weight: 1
        $x_1_2 = "atks.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CobaltStrike_RKB_2147921721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CobaltStrike.RKB!MTB"
        threat_id = "2147921721"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "47.92.131.203" ascii //weight: 1
        $x_1_2 = "Windows.pdb" ascii //weight: 1
        $x_1_3 = "Sent {0} bytes to server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_CobaltStrike_MEL_2147925434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/CobaltStrike.MEL!MTB"
        threat_id = "2147925434"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g('http://47.106.67.138:80/a'))" ascii //weight: 1
        $x_1_2 = "System.Management.Automation.AmsiUtils" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

