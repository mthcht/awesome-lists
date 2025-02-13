rule TrojanSpy_Win32_Nonbolqu_A_2147690912_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Nonbolqu.A"
        threat_id = "2147690912"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nonbolqu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "47C96DB05AFE5E88B0E21BD70E4382A34087" wide //weight: 1
        $x_1_2 = "2A28C26386C0157E8DC7093CEF6C" wide //weight: 1
        $x_1_3 = "BE71B043F4" wide //weight: 1
        $x_1_4 = "D7609454F6" wide //weight: 1
        $x_1_5 = "33CC7BB8508D9E43FB6F" wide //weight: 1
        $x_1_6 = "3CC77FFC2CA924" wide //weight: 1
        $x_1_7 = "5E99AF4FFE5C8D4BE066FC2D" wide //weight: 1
        $x_1_8 = "E2609052F76CE6012EAE20CBAD18B773A1BCE564CE72849032A046F62AD31A" wide //weight: 1
        $x_1_9 = "959194E5024386AC6C" wide //weight: 1
        $x_1_10 = "4BF432C26BE26583BE" wide //weight: 1
        $x_1_11 = "043ECA6591C0DD0E3195" wide //weight: 1
        $x_1_12 = "FA073DF73CAFFC29C002" wide //weight: 1
        $x_1_13 = "3EE81FDC1D4C89A64080" wide //weight: 1
        $x_1_14 = "70BA7185BB1344E6" wide //weight: 1
        $x_1_15 = "C7629E538ECF01" wide //weight: 1
        $x_1_16 = "23D31325DF67E001399AF96F" wide //weight: 1
        $x_1_17 = "49CB6F84BF005E88E46AFC361060F40D3293B91130D267FF59FC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

