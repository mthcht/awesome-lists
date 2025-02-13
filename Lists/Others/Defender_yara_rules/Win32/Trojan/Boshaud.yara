rule Trojan_Win32_Boshaud_A_2147727295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boshaud.A!bit"
        threat_id = "2147727295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boshaud"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" wide //weight: 1
        $x_1_2 = "-Command [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String((Get-ItemProperty HKCU:\\Software)." wide //weight: 1
        $x_1_3 = "powershell -EP b -w hidden -noexit -C for(;;){try{IEX((new-object net.webclient).downloadstring(" wide //weight: 1
        $x_1_4 = " REGWRITE ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

