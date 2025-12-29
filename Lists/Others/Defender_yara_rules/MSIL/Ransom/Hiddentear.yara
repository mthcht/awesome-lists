rule Ransom_MSIL_Hiddentear_PA_2147765379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hiddentear.PA!MTB"
        threat_id = "2147765379"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hiddentear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ren *.xls *.volvo43" wide //weight: 1
        $x_1_2 = "netsh firewall set opmode mode=disable" wide //weight: 1
        $x_1_3 = "tskill /A anti*" wide //weight: 1
        $x_1_4 = "del /Q /F C:\\Program Files\\kaspersky\\*.*" wide //weight: 1
        $x_1_5 = "Your files has been encrypted by using secret encryption method." wide //weight: 1
        $x_1_6 = "temp.bat" wide //weight: 1
        $x_1_7 = "volvo.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_Hiddentear_DA_2147765426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hiddentear.DA!MTB"
        threat_id = "2147765426"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hiddentear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hidden tear" ascii //weight: 1
        $x_1_2 = "ransom.jpg" ascii //weight: 1
        $x_1_3 = "READ_IT.txt.locked" ascii //weight: 1
        $x_1_4 = "http://i.imgur.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Hiddentear_SK_2147960168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hiddentear.SK!MTB"
        threat_id = "2147960168"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hiddentear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hels.readme.txt" ascii //weight: 1
        $x_1_2 = "BLACK-HEOLAS" ascii //weight: 1
        $x_1_3 = "Your important files are locked by encryption" ascii //weight: 1
        $x_1_4 = "BlackHeolasSupport@onionmail.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

