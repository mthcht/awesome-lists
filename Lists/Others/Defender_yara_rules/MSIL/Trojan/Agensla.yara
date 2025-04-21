rule Trojan_MSIL_Agensla_GG_2147767713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GG!MTB"
        threat_id = "2147767713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 09 02 8e 69 5d 02 09 02 8e 69 5d 91 07 09 07 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da [0-5] d6 [0-5] 5d b4 9c 09 15 d6 0d 09 16 2f cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_GG_2147767713_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GG!MTB"
        threat_id = "2147767713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 61 02 09 02 8e 69 5d 02 09 02 8e 69 5d 91 07 09 07 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da 20 ?? ?? ?? 00 28 ?? ?? ?? 06 28 ?? ?? ?? 0a d6 20 ?? ?? ?? 00 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 5d b4 9c 09 15 d6 0d 2b 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_GA_2147768877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GA!MTB"
        threat_id = "2147768877"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fucking" ascii //weight: 1
        $x_1_2 = "MotherFuckerBitch" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "http://liverpoolofcfanclub.com/liverpool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_GA_2147768877_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GA!MTB"
        threat_id = "2147768877"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MARCUS.dll" ascii //weight: 1
        $x_1_2 = "jarico" ascii //weight: 1
        $x_1_3 = "buta" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "GetEntryAssembly" ascii //weight: 1
        $x_1_7 = {d0 a1 d0 b5 d0 bd d1 8c d0 be d1 80 d0 b8 d1 82 d0 b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_GA_2147768877_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GA!MTB"
        threat_id = "2147768877"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_2 = "/C choice /C Y /N /D Y /T" ascii //weight: 10
        $x_10_3 = "\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe" ascii //weight: 10
        $x_10_4 = "schtasks.exe" ascii //weight: 10
        $x_1_5 = "set_UseShellExecute" ascii //weight: 1
        $x_1_6 = ":Zone.Identifier" ascii //weight: 1
        $x_1_7 = "URL=file:///" ascii //weight: 1
        $x_1_8 = "#delay_sec#" ascii //weight: 1
        $x_1_9 = "#installation_method#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Agensla_GC_2147768878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GC!MTB"
        threat_id = "2147768878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://asdcqwdwqx.gq/liverpool-fc-news/features/" ascii //weight: 1
        $x_1_2 = "[SPLITTER]" ascii //weight: 1
        $x_1_3 = "UserAgent:" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_GC_2147768878_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GC!MTB"
        threat_id = "2147768878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select * from Win32_ComputerSystem" ascii //weight: 1
        $x_1_2 = "VirtualBox" ascii //weight: 1
        $x_1_3 = "SbieDll.dll" ascii //weight: 1
        $x_1_4 = "Vmware" ascii //weight: 1
        $x_1_5 = "CreateObject(\"WScript.Shell\").Run" ascii //weight: 1
        $x_1_6 = "S#tartup" ascii //weight: 1
        $x_1_7 = "Sof#tware\\Micr#osoft\\Win#dows\\Curr#entVer#sion\\#R#u#n\\" ascii //weight: 1
        $x_1_8 = "Alloc" ascii //weight: 1
        $x_1_9 = "Write" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_2147771571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.MT!MTB"
        threat_id = "2147771571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d 00 46 72 6f 6d 53 74 72 65 61 6d 00 47 5a 69 70 53 74 72 65 61 6d 00 4d 65 6d 6f 72 79 53 74 72 65 61 6d}  //weight: 1, accuracy: High
        $x_1_2 = "lnDISMCommit" ascii //weight: 1
        $x_1_3 = "REGEXTOKEN_TimestampPrefix" ascii //weight: 1
        $x_1_4 = "FormLib.Baidu" ascii //weight: 1
        $x_1_5 = "mikecel79.wordpress.com" ascii //weight: 1
        $x_1_6 = "chkCaptureVerify" ascii //weight: 1
        $x_1_7 = "/Mount-WIM /ReadOnly /WimFile:" ascii //weight: 1
        $x_1_8 = "Data Source=127.0.0.1;Initial Catalog=Hackathon;User ID=sa;Password=vagrant" ascii //weight: 1
        $x_1_9 = "$10e303b6-20c7-48d0-8a6a-a3e558f16e80" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_MSIL_Agensla_GB_2147777777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GB!MTB"
        threat_id = "2147777777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fucking" ascii //weight: 1
        $x_1_2 = "MotherFuckerBitch" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "liverpool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_GD_2147779235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GD!MTB"
        threat_id = "2147779235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://myliverpoolnews.cf/liverpool-fc-news/features/" ascii //weight: 1
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "UserAgent:" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_GE_2147780171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.GE!MTB"
        threat_id = "2147780171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://ldvamlwhdpetnyn.ml/liverpool-fc-news/features/" wide //weight: 10
        $x_10_2 = "http://xwjhdjylqeypyltby.ml/liverpool-fc-news/features/" wide //weight: 10
        $x_10_3 = "http://bornforthis.ml/liverpool-fc-news/features/" wide //weight: 10
        $x_10_4 = "http://gkfaalkhnkqvgjntywc.ml/liverpool-fc-news/features/" wide //weight: 10
        $x_10_5 = "http://mmwrlridbhmibnr.ml/liverpool-fc-news/features/" wide //weight: 10
        $x_2_6 = "WebClient" ascii //weight: 2
        $x_2_7 = "UserAgent:" ascii //weight: 2
        $x_2_8 = "DownloadString" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Agensla_ABDX_2147787670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.ABDX!MTB"
        threat_id = "2147787670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "astarata.exe" ascii //weight: 1
        $x_1_2 = "Songofthename" ascii //weight: 1
        $x_1_3 = "$3d079790-d72d-44b7-bb93-932ef9d8599b" ascii //weight: 1
        $x_1_4 = "daName" ascii //weight: 1
        $x_1_5 = "TryCallName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_MBFS_2147901468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.MBFS!MTB"
        threat_id = "2147901468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 00 44 00 35 00 41 00 39 00 3a 00 3a 00 33 00 3a 00 3a 00 3a 00 30 00 34 00 3a 00 3a 00 3a 00 46 00 46 00 46 00 46 00 3a 00 3a 00 42 00 38 00 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agensla_PGA_2147939523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agensla.PGA!MTB"
        threat_id = "2147939523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agensla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 13 08 73 ?? 00 00 0a 13 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

