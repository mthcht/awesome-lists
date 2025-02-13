rule TrojanProxy_MSIL_Banker_A_2147658453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:MSIL/Banker.A"
        threat_id = "2147658453"
        type = "TrojanProxy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "txtmodificado.txt" wide //weight: 1
        $x_1_2 = "host, banri" wide //weight: 1
        $x_1_3 = "host, citi" wide //weight: 1
        $x_1_4 = "checkinfect.txt" wide //weight: 1
        $x_1_5 = "PROXY xsenha" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanProxy_MSIL_Banker_B_2147661320_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:MSIL/Banker.B"
        threat_id = "2147661320"
        type = "TrojanProxy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/checkinfect.php" wide //weight: 1
        $x_1_2 = "shExpMatch(host, santa1" wide //weight: 1
        $x_1_3 = "function FindProxyForURL(url, host)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_MSIL_Banker_D_2147679597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:MSIL/Banker.D"
        threat_id = "2147679597"
        type = "TrojanProxy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "210"
        strings_accuracy = "High"
    strings:
        $x_100_1 = ".tudoecology.com\";" wide //weight: 100
        $x_50_2 = "w.identitymusic.co.uk/" wide //weight: 50
        $x_50_3 = "disasterjournal.net/check.php" wide //weight: 50
        $x_40_4 = "var ipsanta = \"PROXY" wide //weight: 40
        $x_40_5 = "ippaypal = \"PROXY" wide //weight: 40
        $x_30_6 = "l-word.com/galleries/lafarewell" wide //weight: 30
        $x_30_7 = "\\x62\\x61\\x6e\\x63\\x6f\\x64\\x6f\\x62\\x72\\x61\\x73\\x69\\x6c" wide //weight: 30
        $x_30_8 = "pos1 = \"*\\x62\"+\"\"+\"\\x62*" wide //weight: 30
        $x_30_9 = "ita1 = \"*\\x69\\x74\\x61\\x75*" wide //weight: 30
        $x_30_10 = "santa2 = \"nder*" wide //weight: 30
        $x_20_11 = "pt.com/pac.jsp" wide //weight: 20
        $x_20_12 = "hotelcosta/check.php" wide //weight: 20
        $x_20_13 = "atomic/check.php" wide //weight: 20
        $x_10_14 = "&netCard=" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_40_*) and 4 of ($x_30_*) and 2 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_40_*) and 4 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_40_*) and 5 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_40_*) and 2 of ($x_30_*) and 3 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_40_*) and 3 of ($x_30_*) and 2 of ($x_20_*))) or
            ((2 of ($x_40_*) and 4 of ($x_30_*) and 1 of ($x_10_*))) or
            ((2 of ($x_40_*) and 4 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_40_*) and 5 of ($x_30_*))) or
            ((1 of ($x_50_*) and 3 of ($x_30_*) and 3 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_50_*) and 4 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_50_*) and 5 of ($x_30_*) and 1 of ($x_10_*))) or
            ((1 of ($x_50_*) and 5 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_50_*) and 1 of ($x_40_*) and 2 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_50_*) and 1 of ($x_40_*) and 3 of ($x_30_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_50_*) and 1 of ($x_40_*) and 3 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_50_*) and 1 of ($x_40_*) and 4 of ($x_30_*))) or
            ((1 of ($x_50_*) and 2 of ($x_40_*) and 1 of ($x_30_*) and 2 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_50_*) and 2 of ($x_40_*) and 1 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_50_*) and 2 of ($x_40_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_50_*) and 2 of ($x_40_*) and 3 of ($x_30_*))) or
            ((2 of ($x_50_*) and 2 of ($x_30_*) and 2 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_50_*) and 2 of ($x_30_*) and 3 of ($x_20_*))) or
            ((2 of ($x_50_*) and 3 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_50_*) and 4 of ($x_30_*))) or
            ((2 of ($x_50_*) and 1 of ($x_40_*) and 3 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_50_*) and 1 of ($x_40_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*) and 1 of ($x_40_*) and 2 of ($x_30_*) and 1 of ($x_10_*))) or
            ((2 of ($x_50_*) and 1 of ($x_40_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_50_*) and 1 of ($x_40_*) and 3 of ($x_30_*))) or
            ((2 of ($x_50_*) and 2 of ($x_40_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_50_*) and 2 of ($x_40_*) and 2 of ($x_20_*))) or
            ((2 of ($x_50_*) and 2 of ($x_40_*) and 1 of ($x_30_*))) or
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 2 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 3 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 4 of ($x_30_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 3 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 2 of ($x_30_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 3 of ($x_30_*))) or
            ((1 of ($x_100_*) and 2 of ($x_40_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_40_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_40_*) and 1 of ($x_30_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_30_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 1 of ($x_30_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_40_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_30_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_MSIL_Banker_E_2147679608_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:MSIL/Banker.E"
        threat_id = "2147679608"
        type = "TrojanProxy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "188.165.140.233\";" wide //weight: 100
        $x_50_2 = "OXY 46.166.146.165\";" wide //weight: 50
        $x_50_3 = "PROXY 94.23.144.228\";" wide //weight: 50
        $x_40_4 = "santa1 = \"*\\x73\\x61\\x6E\\x74\\x61\\x6E\\x64\\x65\\x72*\";" wide //weight: 40
        $x_40_5 = "ban1 = \"*\\x62\\x61\\x6E\\x65\\x73\\x65*\";" wide //weight: 40
        $x_20_6 = "w.atas.fr/karenn/ip.php" wide //weight: 20
        $x_20_7 = "kropus.amarox.ru/temp/ip.php" wide //weight: 20
        $x_20_8 = "pt.com/pac.jsp" wide //weight: 20
        $x_20_9 = "\\extractie\\ieextract.exe" wide //weight: 20
        $x_20_10 = "xupa11 xupa12 xupa4" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_40_*) and 4 of ($x_20_*))) or
            ((2 of ($x_50_*) and 5 of ($x_20_*))) or
            ((2 of ($x_50_*) and 1 of ($x_40_*) and 3 of ($x_20_*))) or
            ((2 of ($x_50_*) and 2 of ($x_40_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 5 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_40_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_40_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_40_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_MSIL_Banker_G_2147679872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:MSIL/Banker.G"
        threat_id = "2147679872"
        type = "TrojanProxy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "function FindProxyForURL(url, host)" wide //weight: 2
        $x_2_2 = "http://www.becollege.info/" wide //weight: 2
        $x_2_3 = "&netCard=" wide //weight: 2
        $x_2_4 = "tfile.jsp" wide //weight: 2
        $x_1_5 = "Banco do Brasil" wide //weight: 1
        $x_1_6 = "Banese" wide //weight: 1
        $x_1_7 = "*citibank*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

