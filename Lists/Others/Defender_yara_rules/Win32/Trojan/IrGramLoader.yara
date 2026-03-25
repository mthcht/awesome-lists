rule Trojan_Win32_IrGramLoader_GVB_2147965582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IrGramLoader.GVB!MTB"
        threat_id = "2147965582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IrGramLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$mDir = \"$env:PUBLIC\\" ascii //weight: 1
        $x_1_2 = "$mLibDir = ($mDir + 'Libraries\\');" ascii //weight: 1
        $x_1_3 = "New-Item $mLibDir -ItemType Directory -ea 0" ascii //weight: 1
        $x_1_4 = "function Check" ascii //weight: 1
        $x_1_5 = "WHILE ((Test-Path (\"$env:TEMP\\ioncheck.log\")) -ne $true)" ascii //weight: 1
        $x_1_6 = "sleep 5" ascii //weight: 1
        $x_1_7 = "del -force -ea 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IrGramLoader_GVC_2147965583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IrGramLoader.GVC!MTB"
        threat_id = "2147965583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IrGramLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set oShell = WScript.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "oShell.run \"powershell -exec bypass -w h -noP -nonI -enc" ascii //weight: 1
        $x_1_3 = "Set oShell = Nothing" ascii //weight: 1
        $x_1_4 = "function Check" ascii //weight: 1
        $x_1_5 = "sleep 3" ascii //weight: 1
        $x_1_6 = "del -force -ea 0" ascii //weight: 1
        $x_1_7 = "| Out-File -Encoding ascii -FilePath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

