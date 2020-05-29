#pragma once
#include <string>
#include <vector>
#include <regex>
#include <map>

class ACLData
{

public:

	ACLData(std::string s_add, std::string d_add, std::string s_port = "notset", std::string d_port = "notset" , std::string s_mask = "32", std::string d_mask = "32");

	//setters
	void set_source_address(std::string srcadd);
	void set_dest_address(std::string destadd);
	void set_source_port(std::string srcport);
	void set_dest_port(std::string destport);
	void set_source_mask(std::string srcmask);
	void set_dest_mask(std::string dstmask);

	//stoi setters
	void set_s_port(int sport);
	void set_d_port(int dport);

	//ip octets to vector<int> setters
	void set_octetToint_src_ip(std::string ip);
	void set_octetToint_dst_ip(std::string ip);
	void set_octetToint_src_mask(std::string ip);
	void set_octetToint_dst_mask(std::string ip);
	std::string wildcard_convert_mask(std::string mask);


	//getters
	std::string get_source_address();
	std::string get_dest_address();
	std::string get_source_port();
	std::string get_dest_port();
	std::string get_source_mask();
	std::string get_dest_mask();

	//ip octets to vector<int> getters
	std::vector<int>* get_octetToint_src_ip();
	std::vector<int>* get_octetToint_dst_ip();


	//stoi getters
	int get_s_port();
	int get_d_port();


	//decimal mask value getter
	int get_src_mask_dec();
	int get_dest_mask_dec();


private:
	//ACL_data
	std::string source_address;
	std::string dest_address;
	std::string source_port;
	std::string dest_port;
	std::string source_mask;
	std::string dest_mask;


	//stoi vals
	int s_port = 0;
	int d_port = 0;

	//ip octets to vector<int>
	std::vector<int> src_ip;
	std::vector<int> dst_ip;

	//mask octets to vector<int>
	std::vector<int> src_mask;
	std::vector<int> dst_mask;




	int src_mask_dec;
	int dest_mask_dec;
	

};

