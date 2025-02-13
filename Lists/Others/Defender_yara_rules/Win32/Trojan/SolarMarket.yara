rule Trojan_Win32_SolarMarket_2147789548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SolarMarket!MTB"
        threat_id = "2147789548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SolarMarket"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "='hBjnKTqfXoEiIHyUmSwQbFutPveORzdYJAcsaxpDWVGLCrNMglZk';$" wide //weight: 1
        $x_1_2 = "=[System.Convert]::FromBase64String([System.IO.File]::ReadAllText($" wide //weight: 1
        $x_1_3 = "));remove-item $" wide //weight: 1
        $x_1_4 = ";for($i=0;$i -lt $" wide //weight: 1
        $x_1_5 = ".count;){for($j=0;$j -lt $" wide //weight: 1
        $x_1_6 = ".length;$j++){$" wide //weight: 1
        $x_1_7 = "[$i]=$" wide //weight: 1
        $x_1_8 = "[$i] -bxor $" wide //weight: 1
        $x_1_9 = "[$j];$i++;if($i -ge $" wide //weight: 1
        $x_1_10 = ".count){$j=$" wide //weight: 1
        $x_1_11 = ".length}}};$" wide //weight: 1
        $x_1_12 = "=[System.Text.Encoding]::UTF8.GetString($" wide //weight: 1
        $x_1_13 = ");iex $" wide //weight: 1
        $x_1_14 = "-command \"" wide //weight: 1
        $x_1_15 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

