rule Trojan_MSIL_Downloader_DAB_2147798710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.DAB!MTB"
        threat_id = "2147798710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\131.exe" ascii //weight: 1
        $x_1_2 = "$70182877-1518-4f4e-99d6-cb38cced4ce8" ascii //weight: 1
        $x_1_3 = "http://sherence.ru/131.exe" ascii //weight: 1
        $x_1_4 = "WindowsFormsApp2.exe" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_DSB_2147798713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.DSB!MTB"
        threat_id = "2147798713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://transfer.sh/get/1O4qNbZ/ass.dll" ascii //weight: 1
        $x_1_2 = "$5c1e247b-9f41-4d4f-9554-4567cab96e11" ascii //weight: 1
        $x_1_3 = "KickAss.exe" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPN_2147798845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPN!MTB"
        threat_id = "2147798845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-128] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "schtasks /create" wide //weight: 1
        $x_1_3 = "netsh advfirewall firewall delete rule" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
        $x_1_5 = "DelegateExecute" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPO_2147798846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPO!MTB"
        threat_id = "2147798846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 6f 00 70 00 34 00 74 00 6f 00 70 00 2e 00 69 00 6f 00 [0-32] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Invoke" wide //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Thread" ascii //weight: 1
        $x_1_6 = "GetResponse" ascii //weight: 1
        $x_1_7 = "WebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPR_2147799297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPR!MTB"
        threat_id = "2147799297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-96] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "LoadLibraryEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPS_2147799298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPS!MTB"
        threat_id = "2147799298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7thpaycommision.com/up/File.png" wide //weight: 1
        $x_1_2 = "EnableGlobal" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "FromBase64String" wide //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPT_2147799299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPT!MTB"
        threat_id = "2147799299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-128] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "Thread" ascii //weight: 1
        $x_1_4 = "GetTypes" ascii //weight: 1
        $x_1_5 = "WriteLine" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPU_2147799300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPU!MTB"
        threat_id = "2147799300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-112] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "WriteByte" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
        $x_1_7 = "LoadLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPV_2147799301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPV!MTB"
        threat_id = "2147799301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "777.exe" wide //weight: 1
        $x_1_3 = "Invoke" wide //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
        $x_1_6 = "builder.pp.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_Downloader_RPV_2147799301_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPV!MTB"
        threat_id = "2147799301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "textbin.net/raw" wide //weight: 1
        $x_1_2 = "wtfismyip.com/text" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "vmware" wide //weight: 1
        $x_1_5 = "VirtualBox" wide //weight: 1
        $x_1_6 = "passwords.txt" wide //weight: 1
        $x_1_7 = "updaterrr.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_CAB_2147799484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.CAB!MTB"
        threat_id = "2147799484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://91.243.44.22/pl-00-92.jpg" ascii //weight: 1
        $x_1_2 = "$529c20e3-0775-4920-8c4e-7ffaa392bc22" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "ConsoleApp7.exe" ascii //weight: 1
        $x_1_5 = "ud2TIMfeBA" ascii //weight: 1
        $x_1_6 = "esaeler/ gifnocpi" ascii //weight: 1
        $x_1_7 = "ping twitter.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_CAC_2147799486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.CAC!MTB"
        threat_id = "2147799486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$dfa07c48-96fd-40eb-aea9-fae0aa8ed778" ascii //weight: 10
        $x_10_2 = "$4c640fb8-c3a2-4bc3-a66a-090af7dfe20d" ascii //weight: 10
        $x_1_3 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "Handler.exe" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Downloader_CAD_2147799487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.CAD!MTB"
        threat_id = "2147799487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$8603A73F-38D8-424D-AF1C-ABC154C09698" ascii //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_1_3 = "sihost.exe" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_5 = "DecryptSimpleString" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "bubiHkHj5y" ascii //weight: 1
        $x_1_8 = "qUh5PruztiVL6" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPM_2147805654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPM!MTB"
        threat_id = "2147805654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "RunPE.RunPE" wide //weight: 1
        $x_1_4 = "RunPE.dll" wide //weight: 1
        $x_1_5 = "pdf.exe" wide //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPM_2147805654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPM!MTB"
        threat_id = "2147805654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-128] 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "GetEnvironmentVariable" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "get_Assembly" ascii //weight: 1
        $x_1_6 = "LoadLibrary" ascii //weight: 1
        $x_1_7 = "Shell" ascii //weight: 1
        $x_1_8 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPK_2147805658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPK!MTB"
        threat_id = "2147805658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 65 00 64 00 69 00 61 00 66 00 69 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 [0-80] 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "LateGet" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPK_2147805658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPK!MTB"
        threat_id = "2147805658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com" wide //weight: 1
        $x_1_2 = "InternetGetCookieExDemo.dll" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "fasfsfs.exe" wide //weight: 1
        $x_1_5 = "manita.nerdesin" wide //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_JIKLU_2147805868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.JIKLU!MTB"
        threat_id = "2147805868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$d24dd28e-cc8c-4b7c-8a1e-23d149c54cf3" ascii //weight: 10
        $x_1_2 = "GetWindows" ascii //weight: 1
        $x_1_3 = "IsASCIILetter" ascii //weight: 1
        $x_1_4 = "GetBitCount" ascii //weight: 1
        $x_1_5 = "IsValidByIri" ascii //weight: 1
        $x_1_6 = "WriteUnicodeString" ascii //weight: 1
        $x_1_7 = "ReadBytes" ascii //weight: 1
        $x_1_8 = "WriteBytes" ascii //weight: 1
        $x_1_9 = "SetWeak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_IHU_2147805869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.IHU!MTB"
        threat_id = "2147805869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$b1447654-6f85-47b1-8f57-fead0e9a4c52" ascii //weight: 10
        $x_1_2 = "Entry" ascii //weight: 1
        $x_1_3 = "Execute" ascii //weight: 1
        $x_1_4 = "FetchFiles" ascii //weight: 1
        $x_1_5 = "MethodInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_INKT_2147806227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.INKT!MTB"
        threat_id = "2147806227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$1ca84c35-cc8d-4323-a2fd-7a7a38571fff" ascii //weight: 10
        $x_1_2 = "ReadInterceptor" ascii //weight: 1
        $x_1_3 = "CreateMapper" ascii //weight: 1
        $x_1_4 = "PrepareMapper" ascii //weight: 1
        $x_1_5 = "get_Czsnqdcx" ascii //weight: 1
        $x_1_6 = "DestroyMapper" ascii //weight: 1
        $x_1_7 = "DisableMapper" ascii //weight: 1
        $x_1_8 = "RunMapper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_CAH_2147806309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.CAH!MTB"
        threat_id = "2147806309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$5801dfb9-8843-47ea-8edb-f4a3cf09499a" ascii //weight: 1
        $x_1_2 = "https://store2.gofile.io/download" ascii //weight: 1
        $x_1_3 = "CAp12.exe" ascii //weight: 1
        $x_1_4 = "InvokeHelper" ascii //weight: 1
        $x_1_5 = "Eucxfyqcvw.dll" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_SILA_2147807214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.SILA!MTB"
        threat_id = "2147807214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$cd180ef7-cfed-410c-a29c-c51c13668410" ascii //weight: 10
        $x_1_2 = "GetAsyncKeyState" ascii //weight: 1
        $x_1_3 = "IsKeyDown" ascii //weight: 1
        $x_1_4 = "keybd_event" ascii //weight: 1
        $x_1_5 = "KeyPress" ascii //weight: 1
        $x_1_6 = "FetchFiles" ascii //weight: 1
        $x_1_7 = "Intrnet" ascii //weight: 1
        $x_1_8 = "MethodInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_SDV_2147808639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.SDV!MTB"
        threat_id = "2147808639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 0d 09 17 59 45 05 00 00 00 01 00 00 00 09 00 00 00 2b 00 00 00 35 00 00 00 3e 00 00 00 2a 28 ?? ?? ?? 0a 0a 2b 40 72 25 00 00 70 28 ?? ?? ?? 06 72 ce 00 00 70 28 ?? ?? ?? 06 14 28 ?? ?? ?? 0a 75 09 00 00 01 0a 2b 1e 1f 10 28 ?? ?? ?? 0a 0a 2b 14 1b 28 ?? ?? ?? 0a 0a 2b 0b 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 02 28 ?? ?? ?? 0a 10 00 02 28 ?? ?? ?? 0a 02 0e 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_BA_2147808813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BA!MTB"
        threat_id = "2147808813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WindowsInternal.ShellCode.EditorDriverLive.exe" ascii //weight: 1
        $x_1_2 = "ThreadStart" ascii //weight: 1
        $x_1_3 = "GetTempFileName" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "GetTempPath" ascii //weight: 1
        $x_1_6 = "GetPathRoot" ascii //weight: 1
        $x_1_7 = "$b84c135b-a8d6-4716-9615-5af0962eb287" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_TF_2147809026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.TF!MTB"
        threat_id = "2147809026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://store2.gofile.io/download" ascii //weight: 1
        $x_1_2 = "Aaron Account" ascii //weight: 1
        $x_1_3 = "DateTime@example.com" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "Kkiupsvwpwwn.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_MSIL_Downloader_TH_2147809027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.TH!MTB"
        threat_id = "2147809027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_2 = "Downlo[]adString" ascii //weight: 1
        $x_1_3 = "Appen[]d" ascii //weight: 1
        $x_1_4 = "UnsafeNativeMethods" ascii //weight: 1
        $x_1_5 = "DebuggingModes" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "Invoke" ascii //weight: 1
        $x_1_8 = "$e8b55f91-c32f-480e-9233-8eaf445549ac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_BC_2147809195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BC!MTB"
        threat_id = "2147809195"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments" ascii //weight: 1
        $x_1_2 = "Error-Log.exe" ascii //weight: 1
        $x_1_3 = "C:\\Vonex\\ErrorLog.exe" ascii //weight: 1
        $x_1_4 = "Vonex.xyz" ascii //weight: 1
        $x_1_5 = "C:\\Users\\Sentiel\\source\\repos\\Vonex-Loader-Console\\Vonex-Loader-Console\\obj\\Debug\\Vonex-Loader-Console.pdb" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
        $x_1_7 = "C:\\Vonex\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_BD_2147809202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BD!MTB"
        threat_id = "2147809202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://91.243.44.22/PL-397.bin" ascii //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "$c13c8c02-868b-4753-a2df-99f6991ae041" ascii //weight: 1
        $x_1_5 = "GetDomain" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_LST_2147809237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.LST!MTB"
        threat_id = "2147809237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 6f 83 0b 00 28 ?? ?? ?? 06 25 26 20 74 83 0b 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 0a 25 26 20 77 83 0b 00 28 ?? ?? ?? 06 25 26 20 7e 83 0b 00 28 ?? ?? ?? 06 25 26 6f ?? ?? ?? 0a 20 81 83 0b 00 28 ?? ?? ?? 06 25 26 20 84 83 0b 00 28 ?? ?? ?? 06 25 26 6f ?? ?? ?? 0a 25 26 20 87 83 0b 00 28 ?? ?? ?? 06 20 8a 83 0b 00 28 ?? ?? ?? 06 25 26 6f ?? ?? ?? 0a 25 26 20 8d 83 0b 00 28 ?? ?? ?? 06 20 96 83 0b 00 28 ?? ?? ?? 06 25 26 6f ?? ?? ?? 0a 25 26 0a 06 28 ?? ?? ?? 0a 25 26 0b 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 0a 25 26 0c 1a 8d 1f 00 00 01 25 16 20 99 83 0b 00 28 ?? ?? ?? 06 20 18 84 0b 00 28 ?? ?? ?? 06 20 33 84 0b 00 28 ?? ?? ?? 06 25 26 28 ?? ?? ?? 0a 25 26 a2 25 17 7e 18 00 00 0a a2 25 18 07 a2 25 19 17 8c 05 00 00 01 a2 0d 08 20 52 84 0b 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_BE_2147809314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BE!MTB"
        threat_id = "2147809314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ethernet or WiFi Network" ascii //weight: 1
        $x_1_2 = "Speed (bits per seconde)" ascii //weight: 1
        $x_1_3 = "BytesReceived: {0}" ascii //weight: 1
        $x_1_4 = "$2f14fccb-38b7-4f2c-840f-7261091c760c" ascii //weight: 1
        $x_1_5 = "edom SOD ni nur eb tonnac margorp sihT!" ascii //weight: 1
        $x_1_6 = "JFTAyWUp5N" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_BF_2147809315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BF!MTB"
        threat_id = "2147809315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://91.243.44.22/PL-93871098.png" ascii //weight: 5
        $x_5_2 = "http://84.252.122.205/xx/ConsoleApp12.bin" ascii //weight: 5
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "get_Assembly" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Downloader_BH_2147809318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BH!MTB"
        threat_id = "2147809318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://www.tractorandinas.com/ajukfjhosgh/ioConsoleApp" ascii //weight: 5
        $x_5_2 = "https://www.uplooder.net/img/image" ascii //weight: 5
        $x_1_3 = "powershell" ascii //weight: 1
        $x_1_4 = "ping yahoo.com" ascii //weight: 1
        $x_1_5 = "ping google.com" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
        $x_1_8 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Downloader_BI_2147809319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BI!MTB"
        threat_id = "2147809319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://91.243.44.22/PL-4uy.bin" ascii //weight: 5
        $x_5_2 = "http://91.243.44.21/grom.bin" ascii //weight: 5
        $x_1_3 = "ping bing.com" ascii //weight: 1
        $x_1_4 = "powershell" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "get_CurrentDomain" ascii //weight: 1
        $x_1_8 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Downloader_BGF_2147809344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BGF!MTB"
        threat_id = "2147809344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "NewMethode" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetType" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "Invoke" ascii //weight: 1
        $x_1_7 = "Pass" ascii //weight: 1
        $x_1_8 = "Yyyy" ascii //weight: 1
        $x_1_9 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_10 = "GetManifestResourceStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_MLC_2147809592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.MLC!MTB"
        threat_id = "2147809592"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "wafaasex" ascii //weight: 1
        $x_1_3 = "wsdf" ascii //weight: 1
        $x_1_4 = "fddfdf" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
        $x_1_6 = "walaa" ascii //weight: 1
        $x_1_7 = "https://drive.google.com/u/0/uc?id=1B0H1zeDvSNEVtoOh6cXXcazX5bspoIWp&export=download" ascii //weight: 1
        $x_1_8 = {00 62 78 78 78 78 78 78 78 78 78 78 78 78 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_MRP_2147809594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.MRP!MTB"
        threat_id = "2147809594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "schtasks /create /sc minute /mo 1 /tn shadowdev /tr" ascii //weight: 2
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_2_3 = "pr0t3_decrypt" ascii //weight: 2
        $x_1_4 = "get_Chars" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_BN_2147810203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BN!MTB"
        threat_id = "2147810203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://tempuri.org/CategorystoreDataSet.xsd" wide //weight: 1
        $x_1_2 = "http://tempuri.org/DashBoardTransactionDataSet.xsd" wide //weight: 1
        $x_1_3 = "C:\\Users\\Administrator\\Desktop\\EasyStore\\obj\\Debug\\Fanko.pdb" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "Fanko.exe" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_BG_2147810303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BG!MTB"
        threat_id = "2147810303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\thedevilcoder.exe" ascii //weight: 1
        $x_1_2 = "RUNNNN" ascii //weight: 1
        $x_1_3 = "thedevilcoder" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "NetworkChange" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "FieldBuilder" ascii //weight: 1
        $x_1_8 = {38 6c dc 8f 0d 4e 81 89 40 67 7b 6b 00 4e 2a 4e 09 67 c1 54 73 54 84 76 ba 4e 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPW_2147810515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPW!MTB"
        threat_id = "2147810515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "prisnov.pt" wide //weight: 1
        $x_1_2 = "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQA" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "DxownxloxadDxatxxax" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPX_2147810516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPX!MTB"
        threat_id = "2147810516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "srotoswinisubarnarekha.com" wide //weight: 1
        $x_1_2 = "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQA" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "DxownxloxadDxatxxax" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_SRX_2147810531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.SRX!MTB"
        threat_id = "2147810531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_2_2 = "pr0t3_decrypt" ascii //weight: 2
        $x_1_3 = "get_Chars" ascii //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_DEGA_2147810533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.DEGA!MTB"
        threat_id = "2147810533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 27 00 00 0a 0b 1e 8d 29 00 00 01 13 07 11 07 16 17 9c 11 07 17 18 9c 11 07 18 19 9c 11 07 19 1a 9c 11 07 1a 1b 9c 11 07 1b 1c 9c 11 07 1c 1d 9c 11 07 1d 1e 9c 11 07 13 05 72 1e 01 00 70 11 05 73 28 ?? ?? ?? 0d 07 09 07 6f ?? ?? ?? 0a 8e b7 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 09 07 6f ?? ?? ?? 0a 8e b7 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 73 2e 00 00 0a 13 06 11 06 07 6f ?? ?? ?? 0a 17 73 30 00 00 0a 0a 00 03 28 ?? ?? ?? 0a 13 04 06 11 04 16 11 04 8e b7 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 11 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c de 10 de 0d 28 ?? ?? ?? 0a 00 28 ?? ?? ?? 0a de 00 00 08 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_RPJ_2147810768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.RPJ!MTB"
        threat_id = "2147810768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "friendpaste.com" wide //weight: 1
        $x_1_2 = "FromBase64String" wide //weight: 1
        $x_1_3 = "EntryPoint" wide //weight: 1
        $x_1_4 = "Invoke" wide //weight: 1
        $x_1_5 = "Windows Defender Realtime Service.exe" wide //weight: 1
        $x_1_6 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_PST_2147810914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.PST!MTB"
        threat_id = "2147810914"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://cdn.discordapp.com/attachments/910787806748639245/910902346681315338/Onana_Hospital_Management_System.dll" ascii //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "exe.xeyap/035889365047555019/107329403492824019/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii //weight: 1
        $x_1_5 = "GetMethod" ascii //weight: 1
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "Invoke" ascii //weight: 1
        $x_1_8 = "ToCharArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_BO_2147811618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BO!MTB"
        threat_id = "2147811618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NBA2K21 HACK by bira" ascii //weight: 1
        $x_1_2 = "DecryptService" ascii //weight: 1
        $x_1_3 = "EncryptService" ascii //weight: 1
        $x_1_4 = "DecryptString" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "MaliciousCheck" ascii //weight: 1
        $x_1_7 = "Obfuscate" ascii //weight: 1
        $x_1_8 = "https://pastebin.com/raw/DWHkw8i1" wide //weight: 1
        $x_1_9 = "EncryptString" ascii //weight: 1
        $x_1_10 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_TE_2147811694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.TE!MTB"
        threat_id = "2147811694"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://113.212.88.60:88/log" ascii //weight: 1
        $x_1_2 = "http://113.212.88.60/Vv/resource.json" ascii //weight: 1
        $x_1_3 = "SELECT username FROM Win32_ComputerSystem" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
        $x_1_6 = "D:\\.000.Private\\000.NET\\VvMain\\q0\\4.0\\VvSvcHost\\VvSvcHost\\obj\\Release\\RuntimeBroker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_TG_2147811695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.TG!MTB"
        threat_id = "2147811695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "heyd.exe" ascii //weight: 1
        $x_1_2 = "Try a different computer!" ascii //weight: 1
        $x_1_3 = "C:\\Users\\X55\\source\\repos\\WindowsFormsApp36\\WindowsFormsApp36\\obj\\Release\\WindowsFormsApp36.pdb" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_6 = "GetTempFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_CRIMB_2147812167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.CRIMB!MTB"
        threat_id = "2147812167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0a 1e 8d 5b 00 00 01 25 d0 5a 00 00 04 28 ?? ?? ?? 0a 0b 73 9a 00 00 0a 0c 00 73 9b 00 00 0a 0d 00 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 20 80 00 00 00 6f ?? ?? ?? 0a 00 28 9e 00 00 0a 72 15 0a 00 70 6f ?? ?? ?? 0a 13 04 11 04 07 20 e8 03 00 00 73 a0 00 00 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f a2 00 00 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 a8 00 00 0a 13 06 00 11 06 03 16 03 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d 11 06 2c 08 11 06 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 0a 00 de 0b 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 00 de 0b 08 2c 07 08 6f ?? ?? ?? 0a 00 dc 06 13 07 2b 00 11 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_SHAZ_2147812170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.SHAZ!MTB"
        threat_id = "2147812170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0a 1e 8d 77 00 00 01 25 d0 e8 00 00 04 28 ?? ?? ?? 0a 0b 73 2b 00 00 0a 0c 00 73 2c 00 00 0a 0d 00 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 20 80 00 00 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 73 00 00 70 6f ?? ?? ?? 0a 13 04 11 04 07 20 e8 03 00 00 73 31 00 00 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 39 00 00 0a 13 06 00 11 06 03 16 03 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d 11 06 2c 08 11 06 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 0a 00 de 0b 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 00 de 0b 08 2c 07 08 6f ?? ?? ?? 0a 00 dc 06 13 07 2b 00 11 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_HMV_2147812860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.HMV!MTB"
        threat_id = "2147812860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "FromBase64String" ascii //weight: 10
        $x_10_2 = "GetType" ascii //weight: 10
        $x_10_3 = "InvokeMember" ascii //weight: 10
        $x_10_4 = "Replace" ascii //weight: 10
        $x_10_5 = {00 42 4e 5a 58 4e 42 5a 58 42 4e 5a 58 42 4e 5a 58 42 4e 58 00}  //weight: 10, accuracy: High
        $x_1_6 = "transfer.sh/get/Bv3XKR/blahdgdsgh.txt" ascii //weight: 1
        $x_1_7 = "transfer.sh/get/T3hH8f/thenewdll.txt" ascii //weight: 1
        $x_1_8 = "transfer.sh/get/YHqpWW/dvikll.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Downloader_SDR_2147813525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.SDR!MTB"
        threat_id = "2147813525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Reverse" ascii //weight: 10
        $x_10_2 = "GetAssemblies" ascii //weight: 10
        $x_10_3 = "GetTypes" ascii //weight: 10
        $x_10_4 = "GetMethods" ascii //weight: 10
        $x_10_5 = "Invoke" ascii //weight: 10
        $x_10_6 = "ToArray" ascii //weight: 10
        $x_2_7 = "/c ping bing.com" wide //weight: 2
        $x_2_8 = "/c ping yahoo.com" wide //weight: 2
        $x_4_9 = "cdn.discordapp.com" ascii //weight: 4
        $x_4_10 = "transfer.sh/get/BSlGm8/SKM-2001112100.png" ascii //weight: 4
        $x_4_11 = "esalog-bg.com/images1/book/gig/a/Criyop.jpg" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((6 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((6 of ($x_10_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Downloader_BL_2147814551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.BL!MTB"
        threat_id = "2147814551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 19 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 25 20 ?? ?? ?? ?? 6f ?? ?? ?? 0a 25 20 ?? ?? ?? ?? 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 28}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 06 07 6f ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 25 8e 69 8d ?? ?? ?? 01 0d 73 ?? ?? ?? 0a 08 16 73 ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 28}  //weight: 1, accuracy: Low
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "DecryptString" ascii //weight: 1
        $x_1_5 = "EncryptString" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_CF_2147816186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.CF!MTB"
        threat_id = "2147816186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://imgur.com/api/upload.xml" ascii //weight: 1
        $x_1_2 = "fb316777154d4a81fe16064fd73ce264" ascii //weight: 1
        $x_1_3 = "Copy external URL(s)" ascii //weight: 1
        $x_1_4 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\KyqheBLeme\\src\\obj\\x86\\Debug\\UTF8Decod.pdb" ascii //weight: 1
        $x_1_5 = "Renaming By Hash" ascii //weight: 1
        $x_1_6 = "mainList_MouseDown" ascii //weight: 1
        $x_1_7 = "DownloadFile" ascii //weight: 1
        $x_1_8 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_NE_2147822242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.NE!MTB"
        threat_id = "2147822242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {15 2c 2a 73 29 00 00 0a 25 72 6d 00 00 70 6f 2a 00 00 0a 25 72 75 00 00 70 6f 2b 00 00 0a 25 17 6f 2c 00 00 0a 25 17 2b 0e 2b 13 2b 18 16 2d d0 16 2d cd 1b 2c ca 2a 6f 2d 00 00 0a 2b eb 28 2e 00 00 0a 2b e6 6f 2f 00 00 0a 2b e1}  //weight: 1, accuracy: High
        $x_1_2 = "P.O-97809886.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Downloader_SQ_2147839577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Downloader.SQ!MTB"
        threat_id = "2147839577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 32 72 27 00 00 70 2b 32 2b 37 2b 3c 17 2d 17 26 2b 3d 16 2b 3d 8e 69 1b 2d 12 26 26 26 2b 36 2b 37 dd 5b 00 00 00 0b 15 2c f3 2b e4 28 2e 00 00 0a 2b ea 28 2f 00 00 0a 2b c7 28 0e 00 00 06 2b c7 6f 30 00 00 0a 2b c2 28 31 00 00 0a 2b bd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

