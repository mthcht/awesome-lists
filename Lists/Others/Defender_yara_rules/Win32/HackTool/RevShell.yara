rule HackTool_Win32_RevShell_HAE_2147980909_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/RevShell.HAE!MTB"
        threat_id = "2147980909"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShell"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$this->shell = 'cmd.exe';" ascii //weight: 5
        $x_4_2 = "= @proc_open($this->shell," ascii //weight: 4
        $x_6_3 = " = new Shell('" ascii //weight: 6
        $x_7_4 = " = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

