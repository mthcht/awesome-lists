rule Trojan_Win32_Clowash_AA_2147896536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clowash.AA!MTB"
        threat_id = "2147896536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clowash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t:\\Controller\\Scaling\\ping\\middleware\\synchroniza\\x64\\release\\clock\\Z\\cli.pdb" ascii //weight: 1
        $x_1_2 = "cmd.exe /c del /F /Q \"%s\"" ascii //weight: 1
        $x_1_3 = "[noservice|console|start|stop|install|remove|running|status]" ascii //weight: 1
        $x_1_4 = "Netcut Defender Anti ARP Spoof Kernal" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

