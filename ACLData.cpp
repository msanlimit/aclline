#include "ACLData.h"



#define RFC1918 0

std::vector<int> ip_to_vec(std::string ip);
bool ip_valid(std::string ip);
bool valid_net_to_mask(std::vector<int>* vec, int mask_dec);

const std::map<std::string, std::string> MASK = {
	{"32","255.255.255.255"},
	{"31","255.255.255.254"},
	{"30","255.255.255.252"},
	{"29","255.255.255.248"},
	{"28","255.255.255.240"},
	{"27","255.255.255.224"},
	{"26","255.255.255.192"},
	{"25","255.255.255.128"},
	{"24","255.255.255.0"},
	{"23","255.255.254.0"},
	{"22","255.255.252.0"},
	{"21","255.255.248.0"},
	{"20","255.255.240.0"},
	{"19","255.255.224.0"},
	{"18","255.255.192.0"},
	{"17","255.255.128.0"},
	{"16","255.255.0.0"},
	{"15","255.254.0.0"},
	{"14","255.252.0.0"},
	{"13","255.248.0.0"},
	{"12","255.240.0.0"},
	{"11","255.224.0.0"},
	{"10","255.192.0.0"},
	{"9","255.128.0.0"},
	{"8","255.0.0.0"},
	{"7","254.0.0.0"},
	{"6","252.0.0.0"},
	{"5","248.0.0.0"},
	{"4","240.0.0.0"},
	{"3","224.0.0.0"},
	{"2","192.0.0.0"},
	{"1","128.0.0.0"}
};


const std::map<std::string, std::string> WILDCARD_MASK = {
	{"255.255.255.254","0.0.0.1"},
	{"255.255.255.252","0.0.0.3"},
	{"255.255.255.248","0.0.0.7"},
	{"255.255.255.240","0.0.0.15"},
	{"255.255.255.224","0.0.0.31"},
	{"255.255.255.192","0.0.0.63"},
	{"255.255.255.128","0.0.0.127"},
	{"255.255.255.0","0.0.0.255"},
	{"255.255.254.0","0.0.1.255"},
	{"255.255.252.0","0.0.3.255"},
	{"255.255.248.0","0.0.7.255"},
	{"255.255.240.0","0.0.15.255"},
	{"255.255.224.0","0.0.31.255"},
	{"255.255.192.0","0.0.63.255"},
	{"255.255.128.0","0.0.127.255"},
	{"255.255.0.0","0.0.255.255"},
	{"255.254.0.0","0.1.255.255"},
	{"255.252.0.0","0.3.255.255"},
	{"255.248.0.0","0.7.255.255"},
	{"255.240.0.0","0.15.255.255"},
	{"255.224.0.0","0.31.255.255"},
	{"255.192.0.0","0.63.255.255"},
	{"255.128.0.0","0.127.255.255"},
	{"255.0.0.0","0.255.255.255"},
	{"254.0.0.0","1.255.255.255"},
	{"252.0.0.0","3.255.255.255"},
	{"248.0.0.0","7.255.255.255"},
	{"240.0.0.0","15.255.255.255"},
	{"224.0.0.0","31.255.255.255"},
	{"192.0.0.0","63.255.255.255"},
	{"128.0.0.0","127.255.255.255"}
};


ACLData::ACLData(std::string s_add, std::string d_add, std::string s_port, std::string d_port, std::string s_mask, std::string d_mask) {

	ACLData::set_source_mask(s_mask);
	ACLData::set_dest_mask(d_mask);

	
	ACLData::set_source_address(s_add);
	ACLData::set_dest_address(d_add);


	if (s_port == "notset") {
		ACLData::source_port = "notset";
	}
	else {
		ACLData::set_source_port(s_port);
	}

	if (d_port == "notset") {
		ACLData::dest_port = "notset";
	}
	else {
		ACLData::set_dest_port(d_port);
	}




}


void ACLData::set_source_address(std::string srcadd) {
	if (ip_valid(srcadd)) {
		set_octetToint_src_ip(srcadd);
		if (valid_net_to_mask(get_octetToint_src_ip(), get_src_mask_dec())) {
			source_address = srcadd;
		}
		else {
			perror("Source IP/mask incorrect.");
			exit(EXIT_FAILURE);
		}
	}
	else {
		perror("Source IP incorrect.");
		exit(EXIT_FAILURE);
	}
}
void ACLData::set_dest_address(std::string destadd) {

	if (ip_valid(destadd)) {
		set_octetToint_dst_ip(destadd);
		if (valid_net_to_mask(get_octetToint_dst_ip(), get_dest_mask_dec())) {
			dest_address = destadd;
		}
		else {
			perror("Destination IP/mask incorrect.");
			exit(EXIT_FAILURE);
		}
	}
	else {
		perror("Destination IP incorrect.");
		exit(EXIT_FAILURE);
	}


}
void ACLData::set_source_port(std::string srcport) {

	try {
		set_s_port(std::stoi(srcport));
	}
	catch (const std::exception& e) {
		printf("Port value is not a number. %s",e.what());
		exit(EXIT_FAILURE);
	}

	if (get_s_port() < 65535 && get_s_port() > 0) {
		source_port = srcport;
	}
	else {
		printf("Wrong port number: %d", get_s_port());
		exit(EXIT_FAILURE);
	}

}
void ACLData::set_dest_port(std::string destport) {

	try {
		set_d_port(std::stoi(destport));
	}
	catch (const std::exception& e) {
		printf("Not number provided to port value.\n %s",e.what());
		exit(EXIT_FAILURE);
	}

	if (get_d_port() < 65535 && get_d_port() > 0) {
		dest_port = destport;
	}
	else {
		printf("Wrong port number: %d", get_d_port());
		exit(EXIT_FAILURE);
	}


}
void ACLData::set_source_mask(std::string srcmask) {
	if (srcmask.length() < 3) {
		auto mask_convert = MASK.find(srcmask);
		if (mask_convert != MASK.end()) {
			source_mask = mask_convert->second;
			src_mask_dec = std::stoi(mask_convert->first);
		}
		else {
			perror("Wrong mask type");
			exit(EXIT_FAILURE);
		}
	}
	else {
		for (auto [k, v] : MASK) {
			if (v == srcmask) {
				source_mask = srcmask;
				src_mask_dec = std::stoi(k);
				break;
			}
		}

		if (source_mask.length() == 0) {
			perror("Wrong mask type");
			exit(EXIT_FAILURE);
		}
	}


}
void ACLData::set_dest_mask(std::string dstmask) {

	if (dstmask.length() < 3) {
		auto mask_convert = MASK.find(dstmask);
		if (mask_convert != MASK.end()) {
			dest_mask = mask_convert->second;
			dest_mask_dec = std::stoi(mask_convert->first);
		}
		else {
			perror("Wrong mask type");
			exit(EXIT_FAILURE);
		}
	}
	else {
		for (auto [k, v] : MASK) {
			if (v == dstmask) {
				dest_mask = dstmask;
				dest_mask_dec = std::stoi(k);
				break;
			}
		}

		if (dest_mask.length() == 0) {
			perror("Wrong mask type");
			exit(EXIT_FAILURE);
		}
	}



}


//stoi setters
void ACLData::set_s_port(int sport) {
	s_port = sport;
}
void ACLData::set_d_port(int dport) {
	d_port = dport;
}

//ip octets to vector<int> setters
void ACLData::set_octetToint_src_ip(std::string ip) {

	src_ip = std::move(ip_to_vec(ip));
}
void ACLData::set_octetToint_dst_ip(std::string ip) {
	dst_ip = std::move(ip_to_vec(ip));
}
void ACLData::set_octetToint_src_mask(std::string ip) {
	src_mask = std::move(ip_to_vec(ip));
}
void ACLData::set_octetToint_dst_mask(std::string ip) {
	dst_mask = std::move(ip_to_vec(ip));
}

std::string ACLData::wildcard_convert_mask(std::string mask) {

	if (auto res = WILDCARD_MASK.find(mask); res != WILDCARD_MASK.end()) {
		return res->second;
	}
	else {
		perror("Mask error wildcard");
		exit(EXIT_FAILURE);
	}


}



//getters

std::string ACLData::get_source_address() {
	return source_address;
}
std::string ACLData::get_dest_address() {
	return dest_address;
}
std::string ACLData::get_source_port() {
	return source_port;
}
std::string ACLData::get_dest_port() {
	return dest_port;
}
std::string ACLData::get_source_mask() {
	return source_mask;
}
std::string ACLData::get_dest_mask() {
	return dest_mask;
}

//ip octets to vector<int> getters
std::vector<int>* ACLData::get_octetToint_src_ip() {
	return &src_ip;
}
std::vector<int>* ACLData::get_octetToint_dst_ip() {
	return &dst_ip;
}


//stoi getters
int ACLData::get_s_port() {
	return s_port;
}
int ACLData::get_d_port() {
	return d_port;
}


//decimal mask value getter
int ACLData::get_src_mask_dec() {
	return src_mask_dec;
}
int ACLData::get_dest_mask_dec() {
	return dest_mask_dec;
}












//some non member func
bool ip_valid(std::string ip) {

	const std::regex ipv4_valid("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

	if (std::regex_match(ip, ipv4_valid)) {
		return true;
	}
	else {
		perror("Incorrect IP! Must be x.x.x.x type with range 0-255 each octet\n");
		exit(EXIT_FAILURE);
	}

	return false;
}





//string ip to vector<int> translator
std::vector<int> ip_to_vec(std::string ip) {

	std::vector<int> vec;
	const char dot = '.';

	unsigned int start = 0;
	unsigned int fof;

	for (int i = 0; i < 4; i++) {
	    fof = ip.find_first_of(dot);

		try {
			vec.push_back(std::stoi(ip.substr(start, fof)));
		}
		catch (std::exception& e) {
			perror(e.what());
			exit(EXIT_FAILURE);
		}

		fof += 1;
		ip.erase(start, fof);
	}
	if (vec.at(0) == 0) {
		perror("Wrong IP\n");
		exit(EXIT_FAILURE);
	}
	return std::move(vec);
}

// validation IP to mask relation
bool valid_net_to_mask(std::vector<int>* vec, int mask_dec) {
	if ((vec->at(3) & 1 << 0) != 0 && mask_dec != 32) {
		return false;
	}
#if RFC1918
	else if (vec->at(0) == 10 || (vec->at(0) == 172 && vec->at(1) > 15 && vec->at(1) < 32) || (vec->at(0) == 192 && vec->at(1) == 168)) {
		return false;
	}
#endif
	switch (mask_dec) {
	default: {
		perror("Unknown error occured\n");
		return false;

	}
	case 32: case 31: {
		return true;
	}
	case 30: {
		if (vec->at(3) == 0 || vec->at(3) % 4 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 29: {
		if (vec->at(3) == 0 || vec->at(3) % 8 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 28: {
		if (vec->at(3) == 0 || vec->at(3) % 16 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 27: {
		if (vec->at(3) == 0 || vec->at(3) % 32 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 26: {
		if (vec->at(3) == 0 || vec->at(3) % 64 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 25: {
		if (vec->at(3) == 0 || vec->at(3) % 128 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 24: case 23: {
		if (vec->at(3) == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 22: {
		if (vec->at(3) == 0 && vec->at(2) % 4 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 21: {
		if (vec->at(3) == 0 && vec->at(2) % 8 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 20: {
		if (vec->at(3) == 0 && vec->at(2) % 16 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 19: {
		if (vec->at(3) == 0 && vec->at(2) % 32 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 18: {
		if (vec->at(3) == 0 && vec->at(2) % 64 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 17: {
		if (vec->at(3) == 0 && vec->at(2) % 128 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 16: case 15: {
		if (vec->at(3) == 0 && vec->at(2) == 0) {
			return true;

		}
		else {
			return false;
		}
	}

	case 14: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) % 4 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 13: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) % 8 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 12: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) % 16 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 11: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) % 32 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 10: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) % 64 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 9: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) % 128 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 8: case 7: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 6: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) == 0 && vec->at(0) % 4 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 5: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) == 0 && vec->at(0) % 8 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 4: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) == 0 && vec->at(0) % 16 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 3: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) == 0 && vec->at(0) % 32 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 2: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) == 0 && vec->at(0) % 64 == 0) {
			return true;

		}
		else {
			return false;
		}
	}
	case 1: {
		if (vec->at(3) == 0 && vec->at(2) == 0 && vec->at(1) == 0 && vec->at(0) % 128 == 0) {
			return true;

		}
		else {
			return false;
		}
	}

	}
}