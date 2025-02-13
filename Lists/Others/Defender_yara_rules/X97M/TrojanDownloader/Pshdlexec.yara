rule TrojanDownloader_X97M_Pshdlexec_2147695458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:X97M/Pshdlexec"
        threat_id = "2147695458"
        type = "TrojanDownloader"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "Pshdlexec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ":80/gkn.html?" ascii //weight: 2
        $x_1_2 = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -noprofile -noexit -c IEX ((New-Object Net.WebClient).DownloadString('" ascii //weight: 1
        $x_1_3 = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX ((New-Object Net.WebClient).DownloadString('" ascii //weight: 1
        $x_4_4 = "Invoke-Shellcode -Payload windows/meterpreter/" ascii //weight: 4
        $x_2_5 = "-Lhost 52.41.122.38 -Lport 443 -Force" ascii //weight: 2
        $x_2_6 = "SetAttr \"C:\\Users\\Public\\config.vbs\", vbHidden" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

