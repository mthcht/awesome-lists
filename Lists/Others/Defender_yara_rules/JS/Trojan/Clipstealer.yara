rule Trojan_JS_Clipstealer_DA_2147930890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:JS/Clipstealer.DA!MTB"
        threat_id = "2147930890"
        type = "Trojan"
        platform = "JS: JavaScript scripts"
        family = "Clipstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "131"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "*screenshot*" wide //weight: 50
        $x_50_2 = "*bitcoin*" wide //weight: 50
        $x_5_3 = "socket.io-client" wide //weight: 5
        $x_5_4 = "windowsHide: true" wide //weight: 5
        $x_5_5 = "import('clipboardy')" wide //weight: 5
        $x_5_6 = "socketServer()" wide //weight: 5
        $x_5_7 = "setInterval(" wide //weight: 5
        $x_5_8 = "makeLog(JSON.stringify(" wide //weight: 5
        $x_1_9 = ".post('http://" wide //weight: 1
        $x_1_10 = ".get('http://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 6 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_JS_Clipstealer_DB_2147932131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:JS/Clipstealer.DB!MTB"
        threat_id = "2147932131"
        type = "Trojan"
        platform = "JS: JavaScript scripts"
        family = "Clipstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "81"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "watchclipboard" wide //weight: 50
        $x_5_2 = "socket.io-client" wide //weight: 5
        $x_5_3 = "windowsHide: true" wide //weight: 5
        $x_5_4 = "import('clipboardy')" wide //weight: 5
        $x_5_5 = "socketServer()" wide //weight: 5
        $x_5_6 = "setInterval(" wide //weight: 5
        $x_5_7 = "makeLog(JSON.stringify(" wide //weight: 5
        $x_1_8 = ".post('http://" wide //weight: 1
        $x_1_9 = ".get('http://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 6 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

