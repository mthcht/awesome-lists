rule Trojan_MSIL_SmallDownloader_EXPL_2147795978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmallDownloader.EXPL!MTB"
        threat_id = "2147795978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmallDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set-MpPreference -ExclusionExtension exe" ascii //weight: 1
        $x_1_2 = "Start-Sleep" ascii //weight: 1
        $x_1_3 = "curl.exe" ascii //weight: 1
        $x_1_4 = "Exploit" ascii //weight: 1
        $x_1_5 = "WebServices" ascii //weight: 1
        $x_1_6 = "get_ExecutablePath" ascii //weight: 1
        $x_1_7 = "set_UseShellExecute" ascii //weight: 1
        $x_1_8 = "Concat" ascii //weight: 1
        $x_1_9 = "powershell" ascii //weight: 1
        $x_1_10 = "/k START" ascii //weight: 1
        $x_1_11 = " & EXIT" ascii //weight: 1
        $x_1_12 = "set_Arguments" ascii //weight: 1
        $x_1_13 = "SoapHttpClientProtocol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmallDownloader_EXPL_2147795978_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmallDownloader.EXPL!MTB"
        threat_id = "2147795978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmallDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadFile" ascii //weight: 1
        $x_1_2 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "GetFolderPath" ascii //weight: 1
        $x_1_5 = "get_Network" ascii //weight: 1
        $x_1_6 = "ToString" ascii //weight: 1
        $x_1_7 = "ServerComputer" ascii //weight: 1
        $x_1_8 = "https://pastebin.com/raw/" ascii //weight: 1
        $x_1_9 = "$79A66B33-78EF-43E5-81A8-635631098639" ascii //weight: 1
        $x_1_10 = "SoapHttpClientProtocol" ascii //weight: 1
        $x_1_11 = "SpecialFolder" ascii //weight: 1
        $x_1_12 = "get_WebServices" ascii //weight: 1
        $x_1_13 = "Process" ascii //weight: 1
        $x_1_14 = "Concat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmallDownloader_EXPI_2147795979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmallDownloader.EXPI!MTB"
        threat_id = "2147795979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmallDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadFile" ascii //weight: 1
        $x_1_2 = "System.Threading" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "HashText" ascii //weight: 1
        $x_1_6 = "SaintSpoofer | Loader" ascii //weight: 1
        $x_1_7 = "https://github.com/tiagopaster/spoofer/raw" ascii //weight: 1
        $x_1_8 = "SaintSpoofer.pdb" ascii //weight: 1
        $x_1_9 = "$9314a34d-eaf0-49b0-bebc-0a77a6bb02b0" ascii //weight: 1
        $x_1_10 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmallDownloader_EXP_2147795980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmallDownloader.EXP!MTB"
        threat_id = "2147795980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmallDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://xz.8dashi.com/" ascii //weight: 1
        $x_1_2 = "CurrentVersion\\Uninstall\\baitushow" ascii //weight: 1
        $x_1_3 = "creating socket" ascii //weight: 1
        $x_1_4 = "download" ascii //weight: 1
        $x_1_5 = "Connecting" ascii //weight: 1
        $x_1_6 = "User-Agent: NSISDL/1.2 (Mozilla)" ascii //weight: 1
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
        $x_1_8 = "Host: xz.8dashi.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmallDownloader_EXPO_2147797368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmallDownloader.EXPO!MTB"
        threat_id = "2147797368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmallDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromImage" ascii //weight: 1
        $x_1_2 = "set_ClientSize" ascii //weight: 1
        $x_1_3 = "NetworkCredential" ascii //weight: 1
        $x_1_4 = "Bitmap" ascii //weight: 1
        $x_1_5 = "ImageFormat" ascii //weight: 1
        $x_1_6 = "SmtpClient" ascii //weight: 1
        $x_1_7 = "Screenshot" ascii //weight: 1
        $x_1_8 = "set_Port" ascii //weight: 1
        $x_1_9 = "set_Host" ascii //weight: 1
        $x_1_10 = "get_Assembly" ascii //weight: 1
        $x_1_11 = "@gmail.com" ascii //weight: 1
        $x_1_12 = "$1b049a5d-b396-460c-a015-35e3999bfed4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmallDownloader_GA_2147812727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmallDownloader.GA!MTB"
        threat_id = "2147812727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmallDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c dir C:\\ >%TEMP%\\dir.txt" ascii //weight: 1
        $x_1_2 = "the process is ended" ascii //weight: 1
        $x_1_3 = "Error {0}: {1}" ascii //weight: 1
        $x_1_4 = "WinSta0\\" ascii //weight: 1
        $x_1_5 = "iplogger.org/" ascii //weight: 1
        $x_1_6 = "http://" ascii //weight: 1
        $x_1_7 = "| OS:" ascii //weight: 1
        $x_1_8 = "| Name:" ascii //weight: 1
        $x_1_9 = "CPU:" ascii //weight: 1
        $x_1_10 = "HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_11 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_MSIL_SmallDownloader_RK_2147819133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmallDownloader.RK!MTB"
        threat_id = "2147819133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmallDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://100threads.000webhostapp.com/test.txt" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Adrian\\source\\repos\\UpdaterPro\\UpdaterPro\\obj\\Debug\\UpdaterPro.pdb" ascii //weight: 1
        $x_1_3 = "cmd.exe" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "UpdaterPro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

