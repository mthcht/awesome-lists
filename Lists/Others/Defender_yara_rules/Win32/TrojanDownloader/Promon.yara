rule TrojanDownloader_Win32_Promon_A_2147575248_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Promon.gen!A"
        threat_id = "2147575248"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Promon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_5_3 = "PROGRA~1\\Slawdog\\SMARTS~1;C:\\Program File" wide //weight: 5
        $x_5_4 = "VictimName=m" wide //weight: 5
        $x_3_5 = "c:\\windows\\drs" wide //weight: 3
        $x_2_6 = "promo.dollarrevenue.com" wide //weight: 2
        $x_2_7 = "promo.dollarrevenue.com" ascii //weight: 2
        $x_1_8 = "http://" wide //weight: 1
        $x_1_9 = "oad.a" wide //weight: 1
        $x_1_10 = "_n_u&i" wide //weight: 1
        $x_1_11 = "oad_sta" wide //weight: 1
        $x_2_12 = "ts.asp?a=a_n_u&exe=" wide //weight: 2
        $x_2_13 = "ad.asp?id=" wide //weight: 2
        $x_2_14 = "ts.asp?exe=" wide //weight: 2
        $x_1_15 = "ad_ei" wide //weight: 1
        $x_1_16 = "nde.a" wide //weight: 1
        $x_2_17 = "d_d.asp?a=d&id=" wide //weight: 2
        $x_2_18 = "/smar" wide //weight: 2
        $x_2_19 = "ats_d.asp?naam=" wide //weight: 2
        $x_1_20 = "&land=" wide //weight: 1
        $x_1_21 = "load_s" wide //weight: 1
        $x_2_22 = "tats.asp?a=a_u&exe=" wide //weight: 2
        $x_10_23 = "h||t||t||p||||:/||/||p||r||o||m||o||.||d||o||l||l||a||r||" wide //weight: 10
        $x_5_24 = "r.||e.||v||.||e||.||n||.||u||.||e||" wide //weight: 5
        $x_10_25 = "||.||c||o||m||/||b||u||n||d||l||e||/||l||o||a||d||e||r||.||e||x||e||" wide //weight: 10
        $x_10_26 = "h{{t{{t{{p{{{{:/{{/{{p{{r{{o{{m{{o{{.{{d{{o{{l{{l{{a{{r{{" wide //weight: 10
        $x_10_27 = "r.{{e.{{v{{.{{e{{.{{n{{.{{u{{.{{e{{" wide //weight: 10
        $x_10_28 = "{{.{{c{{o{{m{{/{{b{{u{{n{{d{{l{{e{{/{{l{{o{{a{{d{{e{{r{{.{{e{{x{{e{{" wide //weight: 10
        $x_10_29 = "<script language=\"JavaScript\" type=\"text/JavaScript\" src=\" http://promo.dollarrevenue.com/drsmartload_js.asp?id=" ascii //weight: 10
        $x_10_30 = "loadfirst=0&recurrence=always&retry=2&retry_mes=You%20must%20click%20Yes%20to%20access%20this%20content\"></script><script language=\"JavaScript\" type=\"text/JavaScript\"> self.focus();\"></script>" ascii //weight: 10
        $x_2_31 = "c:\\drsmartload1.exe" ascii //weight: 2
        $x_2_32 = "%s\\drsmartload2.dat" ascii //weight: 2
        $x_2_33 = "SOFTWARE\\Microsoft\\drsmartload2" ascii //weight: 2
        $x_2_34 = "SOFTWARE\\Microsoft\\DownloadManager" ascii //weight: 2
        $x_1_35 = "%%comspec%%" ascii //weight: 1
        $x_1_36 = "@echo off" ascii //weight: 1
        $x_1_37 = ":repeat" ascii //weight: 1
        $x_1_38 = "del /F /Q \"%%1" ascii //weight: 1
        $x_1_39 = "if exist \"%%1\" goto repeat" ascii //weight: 1
        $x_1_40 = "del /F /Q \"%s" ascii //weight: 1
        $x_1_41 = "%sdelme.bat" ascii //weight: 1
        $x_5_42 = "h--t--t--p----:/--/--p--r--o--m--o--.--d--o--l--l--a--r--" wide //weight: 5
        $x_5_43 = "r.--e.--v--.--e--.--n--.--u--.--e--" wide //weight: 5
        $x_5_44 = "--.--c--o--m--/--b--u--n--d--l--e--/--l--o--a--d--e--r--.--e--x--e--" wide //weight: 5
        $x_5_45 = "c**:**\\**d**r**s**m**a**r**t**l**o**a**d**.**e**x**e 106" wide //weight: 5
        $x_2_46 = "98ui43erf9u8di54re8d9u549rud895ru8jirfd89u54if89ui5489ur" wide //weight: 2
        $x_5_47 = "h::t::t::p:::::/::/::p::r::o::m::o::.::d::o::l::l::a::r" wide //weight: 5
        $x_5_48 = "r.::e.::v::.::e::.::n::.::u::.::e" wide //weight: 5
        $x_5_49 = "c::o::m::/::b::u::n::d::l::e::/::l::o::a::d::e::r::.::e::x::e" wide //weight: 5
        $x_5_50 = "c,:,\\,d,r,s,m,a,r,t,l,o,a,d,.,e,x,e" wide //weight: 5
        $x_5_51 = "c{}:{}\\{}d{}r{}s{}m{}a{}r{}t{}l{}o{}a{}d{}.{}e{}x{}e" wide //weight: 5
        $x_2_52 = "deui h378ory34yf hehgy  yg78g3y h78yeywegqywgei23yed782yfd3" wide //weight: 2
        $x_5_53 = "h+t+t+p+:+/+/+p+r+o+m+o+.+d+o+l+l+a+r" wide //weight: 5
        $x_5_54 = "r.+e.+v+.+e+.+n+.+u+.+e" wide //weight: 5
        $x_5_55 = "+.+c+o+m+/+b+u+n+d+l+e+/+l+o+a+d+e+r+.+e+x+e" wide //weight: 5
        $x_5_56 = "c^:^\\^d^r^s^m^a^r^t^l^o^a^d^.^e^x^e" wide //weight: 5
        $x_5_57 = "h[][][]t[][][]t[][][]p[][][][][][]:/[][][]/[][][]p[][][]r[][][]o[][][]m[][][]o" wide //weight: 5
        $x_5_58 = "r.[][][]e.[][][]v[][][].[][][]e[][][].[][][]n[][][].[][][]u[][][].[][][]e" wide //weight: 5
        $x_5_59 = "c[][][]o[][][]m[][][]/[][][]b[][][]u[][][]n[][][]d[][][]l[][][]e[][][]/[][][]l[][][]o" wide //weight: 5
        $x_5_60 = "c&.&:&.&\\&.&d&.&r&.&s&.&m&.&a&.&r&.&t&.&l&.&o&.&a&.&d&.&.&.&e&.&x&.&e" wide //weight: 5
        $x_5_61 = "c{}{}{}{}:{}{}{}{}\\{}{}{}{}d{}{}{}{}r{}{}{}{}s{}{}{}{}m{}{}{}{}a{}{}{}{}r{}{}{}{}t{}{}" wide //weight: 5
        $x_5_62 = "3oewii9fuipo83rudc89tdufoi54rgvioy45u[dvui54rtfuiytioui54truo54t" wide //weight: 5
        $x_4_63 = {70 00 00 00 02 00 00 00 2f 00 00 00 02 00 00 00 6d 00 00 00 06 00 00 00 20 00}  //weight: 4, accuracy: High
        $x_4_64 = {6f 00 20 00 00 00 06 00 00 00 20 00 61 00 20 00 00 00 06 00 00 00 20 00}  //weight: 4, accuracy: High
        $x_4_65 = {78 00 20 00 00 00 04 00 00 00 20 00 65 00 00 00 00 00 04 00 00 00}  //weight: 4, accuracy: High
        $x_5_66 = {49 00 44 00 00 00 00 00 0e 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 00 00 ec 1a 40 00 00 00 00 00 60 1b 40}  //weight: 5, accuracy: High
        $x_5_67 = {64 00 20 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 6c 00 00 00 02 00 00 00 61 00}  //weight: 5, accuracy: High
        $x_5_68 = {72 00 00 00 04 00 00 00 72 00 20 00 00 00 00 00 06 00 00 00 20 00 65 00 20 00 00 00 06 00 00 00 20 00 76 00 20 00 00 00 06 00 00 00 20 00 6e}  //weight: 5, accuracy: High
        $x_2_69 = "content.dollarrevenue.com/bundle" wide //weight: 2
        $x_2_70 = "Software\\Microsoft\\drsmartload" wide //weight: 2
        $x_2_71 = "c:\\windows\\drsmartload.dat" wide //weight: 2
        $x_2_72 = "smartload_stats.asp?exe=" wide //weight: 2
        $x_2_73 = "smartload_einde.asp?id=" wide //weight: 2
        $x_2_74 = "smartload_stats.asp?a=a_u&exe=" wide //weight: 2
        $x_2_75 = "http://content.dollarrevenue.com/bundle/smartload.asp?id=" wide //weight: 2
        $x_2_76 = "http://content.dollarrevenue.com/bundle/smartload.asp?a=a_n_u&id=" wide //weight: 2
        $x_1_77 = "/donotdelete.asp" wide //weight: 1
        $x_1_78 = "drsmartload.exe" wide //weight: 1
        $x_1_79 = "drsmartload_main" wide //weight: 1
        $x_1_80 = {78 00 20 00 20 00 00 00 0c 00 00 00 20 00 20}  //weight: 1, accuracy: High
        $x_1_81 = {65 00 20 00 20 00 20 00 00 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_82 = {70 00 00 00 02 00 00 00 2f 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_83 = {73 00 00 00 02 00 00 00 6d 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_84 = {61 00 00 00 02 00 00 00 74 00 00 00 02}  //weight: 1, accuracy: High
        $x_1_85 = {78 00 00 00 04 00 00 00 49 00 44 00 00}  //weight: 1, accuracy: High
        $x_1_86 = {0e 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f}  //weight: 1, accuracy: High
        $x_1_87 = {2f 00 00 00 10 00 00 00 20 00 61 00 63 00 74}  //weight: 1, accuracy: High
        $x_1_88 = {69 00 76 00 65 00 78 00 00 00 00 00 56 42 41 36}  //weight: 1, accuracy: High
        $x_1_89 = {64 00 20 00 20 00 00 00 0a 00 00 00 20 00 20}  //weight: 1, accuracy: High
        $x_1_90 = {72 00 20 00 20 00 00 00 0a 00 00 00 20 00 20}  //weight: 1, accuracy: High
        $x_1_91 = {73 00 20 00 20 00 00 00 0e 00 00 00 20 00 20 00 6d}  //weight: 1, accuracy: High
        $x_1_92 = {6c 00 00 00 04 00 00 00 6c 00 61}  //weight: 1, accuracy: High
        $x_1_93 = {00 00 00 00 06 00 00 00 20 00 65 00 20}  //weight: 1, accuracy: High
        $x_1_94 = {06 00 00 00 20 00 76 00 20 00 00 00 06}  //weight: 1, accuracy: High
        $x_1_95 = {20 00 6e 00 20 00 00 00 04 00 00 00 75}  //weight: 1, accuracy: High
        $x_2_96 = {37 35 72 6c 6d 6f 6e 00 00 00 00 00 00 13 00 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((8 of ($x_2_*))) or
            ((1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 7 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*))) or
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

