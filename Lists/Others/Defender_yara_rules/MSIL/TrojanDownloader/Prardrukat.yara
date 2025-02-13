rule TrojanDownloader_MSIL_Prardrukat_A_2147696649_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Prardrukat.A"
        threat_id = "2147696649"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Prardrukat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "art.duckart168.com/pic/index.htm" wide //weight: 4
        $x_2_2 = "ShutDown -s -t 15 -f -c" wide //weight: 2
        $x_2_3 = "\\00000from2boot.txt" wide //weight: 2
        $x_2_4 = "057E36487DC31039731213FF661D544C3108" wide //weight: 2
        $x_2_5 = "Options\\taskkill.exe\" /v debugger /d null /f" wide //weight: 2
        $x_1_6 = "Lineagehelp" wide //weight: 1
        $x_1_7 = "96af6e24966fa75deec5f7e3b1450690" wide //weight: 1
        $x_1_8 = "1bf624418473ab35c7bac82a437d5531" wide //weight: 1
        $x_1_9 = "d3df887ed11e617945acfc322c70be31" wide //weight: 1
        $x_1_10 = "ac7aca7c508ce42dbe780db47f570797" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

