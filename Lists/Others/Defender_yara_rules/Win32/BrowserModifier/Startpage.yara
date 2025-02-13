rule BrowserModifier_Win32_Startpage_11642_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Startpage"
        threat_id = "11642"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {86 51 e9 b6 85 3c 5b 5f 33 c9 59 bd 5f 28 73 99 4e 25 64 6e 61 24 a8 61 75 3f aa ee 34}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4c 24 08 8a 01 56 2c 39 57 8b 7c 24 0c 0f b6 f0 56 8d 41 01 50 57 6a 01 51 e8 27 ff ff ff 83 c4 14 c6 44 3e ff 00 8b c7 5f 5e c3}  //weight: 2, accuracy: High
        $x_2_3 = ",DllInstall" ascii //weight: 2
        $x_2_4 = {73 65 61 72 63 68 2d 70 69 6e 28 [0-4] 29 2e 64 6c 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Startpage_11642_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Startpage"
        threat_id = "11642"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "00000002-0001-0002-0000-0000F8F3557B}" ascii //weight: 2
        $x_2_2 = "PROTOCOLS\\Filter\\text/html" ascii //weight: 2
        $x_5_3 = "  alert(\"Please specify something to search for!\");" ascii //weight: 5
        $x_2_4 = "function go(text) { formWeb.ww.value=text;" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Startpage_11642_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Startpage"
        threat_id = "11642"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".homepage\", \"%url%\"); >> \"%APPDATA%\\Mozilla\\Firefox\\" ascii //weight: 1
        $x_1_2 = "cmd.exe /c del URLSetter.bat" ascii //weight: 1
        $x_1_3 = "echo \"Start Page\"=\"%url%\" >> IE_HomePage_Reset.reg" ascii //weight: 1
        $x_1_4 = "REGEDIT /S IE_HomePage_reset.reg " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Startpage_A_153120_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Startpage.A"
        threat_id = "153120"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
        $x_1_2 = "Start Page" wide //weight: 1
        $x_1_3 = "http://www.taktuk.tk" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "virus total" wide //weight: 1
        $x_1_6 = "project.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

