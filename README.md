# Lab1NetworkPacketEditor 
# Emil Fransson

För att kompilera och länka, ange helt enkelt "make".
För att exekvera den färdiga filen main.exe, ange "./main".

"make test" kommer kompilera, länka och bygga till exekverbar fil för att därefter köra filen med ett extra argument. I koden innebär detta helt enkelt att en int sätts till ett visst tal, som koden därefter kontrollerar mot, för att konstatera huruvida det är test-versionen som körs eller ej. Det är en ganska "rough" metod, men den gör sitt jobb.
Vad det innebär rent praktiskt är att filen "NetworkDump.pcap" kommer läsas in i minnet, ett packet med protokollet UDP kommer läggas till korrekt sist i minnet, och därefter kommer allting att skrivas till en ny "Test.pcap"-fil. Notera att de inledande 5 paketen som läses in är plockade från wireshark så det finns en god sannolikhet att wireshark kommer ha ett och annat att påstå om dem. De är ju enbart inlästa och utlästa så att säga. Paketet som läggs till är ju däremot helt korrekt behandlat i funktionerna och kommer att generera ett korrekt resultat såväl inne i programmet som i wireshark.

GITHUB REPO: https://github.com/EmilFransson/Lab1NetworkPacketEditor
(Samma som namnet på mappen som ingår i inlämningen)
 
