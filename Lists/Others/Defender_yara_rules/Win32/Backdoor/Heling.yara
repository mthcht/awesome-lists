rule Backdoor_Win32_Heling_A_2147694318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Heling.A.gen!dha"
        threat_id = "2147694318"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Heling"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stop %s&sc delete %s&ping 127.0.0.1 -n 5&del /a /f \"%s\"" ascii //weight: 1
        $x_1_2 = "&uid=%s&lan=%s&hname=%s&uname=%s&os=%s&proxy=%s&ver=%s" ascii //weight: 1
        $x_1_3 = "action=A3VazqiUnGLIZyFZ" ascii //weight: 1
        $x_1_4 = "action=CqQdfh53Zt7rc89a" ascii //weight: 1
        $x_1_5 = "action=E7DCQhX1Duj9N32q" ascii //weight: 1
        $x_1_6 = "action=nG0WVXSWGa9rGSmt" ascii //weight: 1
        $x_1_7 = "action=oQcIrL5nLjBj0YpQ" ascii //weight: 1
        $x_1_8 = "action=QoIcRr3nJUEJ6KxM" ascii //weight: 1
        $x_1_9 = "action=QSPgAF634ntoTmJl" ascii //weight: 1
        $x_1_10 = "config sleeptime ok, and the current sleeptime is %d" ascii //weight: 1
        $x_1_11 = "set the current sleeptime is %d show" ascii //weight: 1
        $x_1_12 = "[%s] the file uploaded successfully !" ascii //weight: 1
        $x_1_13 = "[%s] the file downloaded successfully !" ascii //weight: 1
        $x_1_14 = "philippinenews.mooo.com" ascii //weight: 1
        $x_1_15 = "xweber_server.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Heling_B_2147694319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Heling.B.gen!dha"
        threat_id = "2147694319"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Heling"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[UpdateWeb]" ascii //weight: 1
        $x_1_2 = "[FakeDomain]" ascii //weight: 1
        $x_1_3 = "[ListenMode]" ascii //weight: 1
        $x_1_4 = "//1234/config.htm" ascii //weight: 1
        $x_2_5 = "xsl exe service global event" ascii //weight: 2
        $x_2_6 = "xsl dll service global event" ascii //weight: 2
        $x_1_7 = "now:%d start:%d end:%d" ascii //weight: 1
        $x_1_8 = "Windows NT 5.1; SV1; Maxthon; XSL:" ascii //weight: 1
        $x_1_9 = "XSLCmd" ascii //weight: 1
        $x_1_10 = "XSLPlug" ascii //weight: 1
        $x_1_11 = "XSLAuto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

