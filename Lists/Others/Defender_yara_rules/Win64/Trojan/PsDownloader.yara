rule Trojan_Win64_PsDownloader_CAMO_2147847643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PsDownloader.CAMO!MTB"
        threat_id = "2147847643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PsDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cABvAHcAZQByAHMAaABlAGwAbAAgAC0ARQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBjAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdA" ascii //weight: 1
        $x_1_2 = "ByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxADAALgAyADoAOAAwAC8AcgBlAHYAXwBzAGgAZQBsAGwALgB0AHgAdAAnACkA" ascii //weight: 1
        $x_1_3 = "powershell -nop -exec bypass -w hidden -e" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\cmd.exe /c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PsDownloader_CH_2147941771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PsDownloader.CH!MTB"
        threat_id = "2147941771"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PsDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$badWords = @('john','abby','bruno','george','azure','1280x1024','john doe','display adapter','hyper-v','vmware','virtualbox','kvm','qemu','xen','parallels'," ascii //weight: 5
        $x_5_2 = "$env:COMPUTERNAME.ToLower();foreach($w in $badWords){if($c.Contains($w)){$matches+=\"Computer: $w\"}};try {$gpus = Get-CimInstance Win32_VideoController" ascii //weight: 5
        $x_2_3 = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command \"$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri 'http" ascii //weight: 2
        $x_2_4 = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

