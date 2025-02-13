rule TrojanSpy_MSIL_Irstil_A_2147696772_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Irstil.A"
        threat_id = "2147696772"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Irstil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "127.0.0.1 zenavotata.in" ascii //weight: 1
        $x_1_2 = "127.0.0.1 eworld.webspiderasia.co.in" ascii //weight: 1
        $x_1_3 = "127.0.0.1 iconworld.asia" ascii //weight: 1
        $x_1_4 = "127.0.0.1 ngen2014.asia" ascii //weight: 1
        $x_1_5 = "127.0.0.1 zenevotata.in" ascii //weight: 1
        $x_1_6 = "127.0.0.1 spiderhispider.in" ascii //weight: 1
        $x_1_7 = "127.0.0.1 blacktswithforrest.com" ascii //weight: 1
        $x_1_8 = "127.0.0.1 myticketworld2015.com" ascii //weight: 1
        $x_2_9 = "http://70.38.40.185" ascii //weight: 2
        $x_2_10 = "ipconfig /flushdns" ascii //weight: 2
        $x_2_11 = "Hide My Ass Proxy List" ascii //weight: 2
        $x_1_12 = "State Bank of India" ascii //weight: 1
        $x_1_13 = "HDFC Bank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Irstil_B_2147697655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Irstil.B"
        threat_id = "2147697655"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Irstil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd=getiplist&ch=GURU&lic=" wide //weight: 1
        $x_1_2 = "cmd=sethdv&hdv=" wide //weight: 1
        $x_1_3 = "&screen=bookTicket&browser=::: Konqueror / Safari / OmniWeb 4.5+ ::: and Operating System is  :   Windows&pressedGo=&changetext" wide //weight: 1
        $x_1_4 = "getogetherforreunionathome.in/match.asp" wide //weight: 1
        $x_1_5 = "Ecom_Payment_Card_ExpDate_Year" wide //weight: 1
        $x_1_6 = "&--=Railway tkt booking&statusCount=&debit" wide //weight: 1
        $x_1_7 = "Default.aspx?cmd=strans&un=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

