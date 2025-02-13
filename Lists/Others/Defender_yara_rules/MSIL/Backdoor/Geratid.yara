rule Backdoor_MSIL_Geratid_A_2147655352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Geratid.A!dll"
        threat_id = "2147655352"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Geratid"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "414"
        strings_accuracy = "High"
    strings:
        $x_200_1 = {48 61 72 64 77 61 72 65 49 44 00 52 41 54 49 44 00 57 65 62 49 6e 74 65 72 70 72 65 74 65 72}  //weight: 200, accuracy: High
        $x_200_2 = "IdentificationFromURL" ascii //weight: 200
        $x_50_3 = {75 6e 6c 6f 63 6b 41 73 73 69 73 74 42 69 6e 00 75 6e 6c 6f 63 6b 41 73 73 69 73 74 4e 61 6d 65}  //weight: 50, accuracy: High
        $x_50_4 = {52 75 6e 42 61 74 63 68 00 76 61 6c 75 65 73 00 44 69 73 63 6f 6e 6e 65 63 74 00 45 78 65 63 46 72 6f 6d 55 72 6c}  //weight: 50, accuracy: High
        $x_4_5 = "\"C:\\Windows\\iexplore.exe\"" ascii //weight: 4
        $x_4_6 = "get_FirewallName" ascii //weight: 4
        $x_4_7 = "SELECT * FROM AntivirusProduct" wide //weight: 4
        $x_4_8 = "_PUBLIC1229" wide //weight: 4
        $x_4_9 = "KillProcessFromFileInfo" ascii //weight: 4
        $x_1_10 = "get_AVName" ascii //weight: 1
        $x_1_11 = "SetRATID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_200_*) and 3 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_200_*) and 4 of ($x_4_*))) or
            ((2 of ($x_200_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Geratid_A_2147655353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Geratid.A"
        threat_id = "2147655353"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Geratid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "360,beat,dw20,dwwin,kav,malware,ntvdm,pcts" ascii //weight: 20
        $x_20_2 = "RATID.SetIdentification(RAT_KEY, newId)" ascii //weight: 20
        $x_2_3 = "helmolannaduri.servehttp.com/announce/" ascii //weight: 2
        $x_2_4 = "hwid=\" & HWID & \"&rid=\" & RATID & \"&rno=\" & RATNO" ascii //weight: 2
        $x_2_5 = "{\"NeroCheck\", \"lsasss\"}" ascii //weight: 2
        $x_2_6 = "IDs.Add(\"Tencent\")" ascii //weight: 2
        $x_2_7 = "(New String(){\"AdobeARM.exe\"})" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

