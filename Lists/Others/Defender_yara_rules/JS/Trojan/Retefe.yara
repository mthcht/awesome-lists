rule Trojan_JS_Retefe_C_2147750924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:JS/Retefe.C"
        threat_id = "2147750924"
        type = "Trojan"
        platform = "JS: JavaScript scripts"
        family = "Retefe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\mshta.exe" wide //weight: 1
        $x_1_2 = "vbscript:close(CreateObject(WScript.Shell).Run(" wide //weight: 1
        $x_1_3 = "powershell.exe" wide //weight: 1
        $x_1_4 = "=$env:Temp+'\\" wide //weight: 1
        $x_1_5 = ".DownloadFile('http://127.0.0.1:5" wide //weight: 1
        $x_1_6 = ".asp?" wide //weight: 1
        $x_1_7 = "&ip='+" wide //weight: 1
        $x_1_8 = "String('http://api.ipify.org/'),$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

