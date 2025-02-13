rule Trojan_PowerShell_Empire_A_2147730381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Empire.A!!Empire.gen!A"
        threat_id = "2147730381"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Empire"
        severity = "Critical"
        info = "Empire: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stage1response" ascii //weight: 1
        $x_1_2 = "stage2Response" ascii //weight: 1
        $x_1_3 = "DotNetEmpire" ascii //weight: 1
        $x_1_4 = "StartAgentJob" ascii //weight: 1
        $x_1_5 = "EmpireStager" ascii //weight: 1
        $x_1_6 = "set_EnablePrivileges" ascii //weight: 1
        $x_1_7 = "get_DefaultCredentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_Empire_A_2147730381_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Empire.A!!Empire.gen!A"
        threat_id = "2147730381"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Empire"
        severity = "Critical"
        info = "Empire: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "function start-negotiate {param($" wide //weight: 1
        $x_1_2 = "[reflection.assembly]::loadwithpartialname(\"system.security\")" wide //weight: 1
        $x_1_3 = "[system.net.webrequest]::getsystemwebproxy()" wide //weight: 1
        $x_1_4 = ".headers.add(\"user-agent\",$" wide //weight: 1
        $x_1_5 = "@(0x01,0x02,0x00,0x00)" wide //weight: 1
        $x_1_6 = "@(0x01,0x03,0x00,0x00)" wide //weight: 1
        $x_1_7 = "='0.0.0.0'}" wide //weight: 1
        $x_1_8 = ".getstring($(decrypt-bytes -key $key -in $raw)" wide //weight: 1
        $x_1_9 = "invoke-empire -servers @(" wide //weight: 1
        $x_1_10 = "-stagingkey $sk -sessionkey $key -sessionid $id -workinghours" wide //weight: 1
        $x_1_11 = "start-negotiate -" wide //weight: 1
        $x_1_12 = {5b 00 47 00 43 00 5d 00 3a 00 3a 00 43 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 28 00 29 00 3b 00 [0-32] 20 00 2d 00 53 00 65 00 72 00 76 00 65 00 72 00 73 00 20 00 40 00 28 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

