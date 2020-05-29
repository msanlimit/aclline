// CiscoIOS_ACLline_add.cpp : This file contains the 'main' function. Program execution begins and ends there.
//



#define LIBSSH_STATIC 1
#include <libssh/libssh.h>

#include <string>
#include <iostream>
#include <fstream>
#include <vector>



#include "ACLData.h"

#define MIN_ID 6000
#define MAX_ID 70000
#define program_name "acldata"

struct AclValz {
    std::string source_address;
    std::string dest_address;
    std::string source_port = "notset";
    std::string dest_port = "notset";
    std::string source_mask = "32";
    std::string dest_mask = "32";
};


//file to store ACL id
const std::string IDfilename = "id.txt";


//read write file
std::string open_to_read();
void open_to_write(std::string input);

//Parameters parse and help
void Param_parse(int argc, char* const* argv, int& flags, AclValz& values);
void help_version(int status);

//ACL string generator
std::vector<std::string> line_generator(std::shared_ptr<ACLData>& data);

//SSH connection
int ssh_connect(std::vector<std::string>& acl_lines, std::string ID);
int interactive_shell_session(ssh_channel channel);
int write_to_channel(ssh_channel channel, const char* chars);





int main(int argc, char* argv[])
{

    AclValz values;


    int flags = 0;

    Param_parse(argc, argv, flags, values);



    std::shared_ptr<ACLData> data_instance = std::make_shared<ACLData>(values.source_address, values.dest_address, values.source_port, values.dest_port, values.source_mask, values.dest_mask);

    std::string fileop = open_to_read();

    std::vector<std::string> lines = line_generator(data_instance);

   // std::cout << "\n" << data_instance->get_source_address() << "\t" << data_instance->get_dest_address() << "\t" << data_instance->get_source_port() << "\t" << data_instance->get_dest_port() << "\t" << data_instance->get_source_mask() << "\t" << data_instance->get_dest_mask() << std::endl;


    while (true) {

        if (int rc = ssh_connect(lines,fileop); rc == 5) {

            open_to_write(fileop);
            return(EXIT_SUCCESS);
        }
        else if (rc == -69) {
            fileop = std::to_string((std::stoi(fileop) + 1));
            printf("ACL line is not empty. Line number was increased +1.\n");
        }
        else {

            exit(SSH_ERROR);
        }

    }



    return 0;
}

//read aclID from file id.txt
std::string open_to_read() {

    std::ifstream infile(IDfilename,std::ifstream::in);
    bool valid = false;
    int i_id;
    if (infile.is_open()) {
        char id[10];
        infile.getline(id, 10);
        std::string s_id(id);
        try {
           i_id = std::stoi(s_id);
        }
        catch (std::exception& e) {
            printf("ID is incorrect.\n%s",e.what());
            exit(EXIT_FAILURE);
        }
        i_id++;
        while (!valid) {
            if (i_id > MAX_ID) {
                perror("ID higher than maximum value of 70000.");
                exit(EXIT_FAILURE);
            }
            else if (i_id % 10 == 0 || i_id < MIN_ID) {
                i_id++;
            }
            else {
                valid = true;

            }
        }

        infile.close();

        return std::to_string(i_id);

    }
    else {
        perror("Error! File reading problem.");
        exit(EXIT_FAILURE);
    }

}

//write used ID to id.txt with replacement previous one(usually previous ID + 1)
void open_to_write(std::string input) {

    std::ofstream onfile(IDfilename, std::ofstream::trunc);
    if (onfile.is_open()) {
        onfile << input;
    }
    else {
        perror("Error! File writing problem.");
        exit(EXIT_FAILURE);
    }
}


std::vector<std::string> line_generator(std::shared_ptr<ACLData> &data) {

    std::string init_line = " permit tcp";

    std::string end_line = "\n";

    std::string from = " ";
    if (std::string sip = data->get_source_mask(); sip == "255.255.255.255") {
        from += ("host " + data->get_source_address());
    }
    else {
        from += (data->get_source_address() + " " + (data->wildcard_convert_mask(data->get_source_mask())));
    }

    if (std::string sport = data->get_source_port(); sport != "notset") {
        from += (" eq " + sport);
    }



    std::string to = " ";
    if (std::string dip = data->get_dest_mask(); dip == "255.255.255.255") {
        to += ("host " + data->get_dest_address());
    }
    else {
        to += (data->get_dest_address() + " " + (data->wildcard_convert_mask(data->get_dest_mask())));
    }

    if (std::string dport = data->get_dest_port(); dport != "notset") {
        to += (" eq " + dport);
    }

    std::vector<std::string> lines;

    lines.push_back(init_line + from + to + end_line);
    lines.push_back(init_line + to + from + end_line);

    return std::move(lines);

}






int ssh_connect(std::vector<std::string>& acl_lines,std::string ID) {

    //initial variables
    const char* username = "test";
    const char* password = "test123";
    const std::string ip_addr = "172.16.2.100";
    int port = 22;
    int rc;
    int verbosity = SSH_LOG_PROTOCOL;

    // config lines
    const char* conf = "conf t\n";
    const char* acl_name_in = "ip access-list ex test-in\n";
    const char* acl_name_out = "ip access-list ex test-out\n";
    const char* end = "end\n";

    const char* console_exit = "exit\n";







    ssh_session my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);

    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST,ip_addr.c_str());
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, &username);

    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting to localhost: %s\n",
            ssh_get_error(my_ssh_session));
        return(SSH_ERROR);
    }


    rc = ssh_userauth_password(my_ssh_session, username, password);

    if (rc == SSH_OK) {
        std::cout << "Connected success!";
    }
    else {
        fprintf(stderr, "Error connecting to localhost: %s\n",
            ssh_get_error(my_ssh_session));
        return(SSH_ERROR);
    }



    ssh_channel channel;

    channel = ssh_channel_new(my_ssh_session);
    if (channel == NULL) return SSH_ERROR;
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        return rc;
    }

    rc = interactive_shell_session(channel);

    if (ssh_channel_is_open(channel)) {



        rc = write_to_channel(channel, conf);

        //access list input line add
        rc = write_to_channel(channel, acl_name_in);
        rc = write_to_channel(channel, ((ID + acl_lines.at(0)).c_str()));
        //access list output line add
        rc = write_to_channel(channel, acl_name_out);
        rc = write_to_channel(channel, ((ID + acl_lines.at(1)).c_str()));


        rc = write_to_channel(channel, end);


        rc = write_to_channel(channel, console_exit);



        char buffer[512];
        std::string buf;
        std::string s_buf;
        int nbytes;



        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        s_buf += buf.assign(buffer, 0, nbytes);
        while (nbytes > 0)
        {

            if (fwrite(buffer, 1, nbytes, stdout) != nbytes)
            {
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return SSH_ERROR;
            }
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
            s_buf += buf.assign(buffer, 0, nbytes);

        }

        if (nbytes < 0)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return SSH_ERROR;
        }

        std::string ID_error = "Duplicate sequence number";
        if (int err = s_buf.find(ID_error); err != std::string::npos) {
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);

            ssh_disconnect(my_ssh_session);
            ssh_free(my_ssh_session);
            return -69;
        }

    }


    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);

    return rc;
}


int interactive_shell_session(ssh_channel channel)
{
    int rc;

    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) return rc;

    rc = ssh_channel_change_pty_size(channel, 80, 24);
    if (rc != SSH_OK) return rc;

    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) return rc;



    return rc;
}


int write_to_channel(ssh_channel channel, const char* chars) {


    int bytes;

    size_t c_size = strlen(chars);

    bytes = ssh_channel_write(channel, chars, c_size);

    return bytes;
}















//parsing parameters
void Param_parse(int argc, char* const* argv, int& flags, AclValz& values) {

    if (argc < 5) {
        help_version(EXIT_SUCCESS);
    }


    if (argc % 2 != 0) {


        for (int i = 1; i < argc; i += 2) {
            if (argv[i][0] != '-') {
                printf("Parameter error: %s", argv[i]);
                exit(EXIT_FAILURE);
            }
            else {
                switch (char temp = argv[i][1]) {
                default: {
                    help_version(EXIT_FAILURE);
                }
                case 's': {
                    flags |= 1UL << 0;
                    values.source_address = argv[i + 1];
                    break;
                }
                case 'd': {
                    flags |= 1UL << 1;
                    values.dest_address = argv[i + 1];
                    break;
                }
                case 'o': {
                    flags |= 1UL << 2;
                    values.source_port = argv[i + 1];
                    break;
                }
                case 'e': {
                    flags |= 1UL << 3;
                    values.dest_port = argv[i + 1];
                    break;
                }
                case 'u': {
                    flags |= 1UL << 4;
                    values.source_mask = argv[i + 1];
                    break;
                }
                case 't': {
                    flags |= 1UL << 5;
                    values.dest_mask = argv[i + 1];
                    break;
                }

                }
            }
        }

    }
    else {
        help_version(EXIT_FAILURE);
    }




}
//help lines
void help_version(int status) {

    printf("Usage: %s [OPTION]...\n", program_name);
    fputs("\
    \n\
 Add permit rule to ACL with line number selection.\n\
     \n\
     -s          Source IP address\n\
     -d          Destination IP address\n\
     -o          Source port\n\
     -e          Destination port\n\
     -u          Source mask\n\
     -t          Destination mask\n\
     ", stdout);
    printf("\
    \n\
 Examples:\n\
    %s -s 192.168.1.1 -d 172.16.1.1                                          Add host-to-host permit rule(all ports).\n\
    %s -s 192.168.1.1 -d 172.16.1.1 -o 555 -e 80                             Add host-to-host permit rule with source/destination port set.\n\
    %s -s 192.168.1.0 -d 172.16.1.0 -o 555 -e 80 -u 24 -t 255.255.255.224    Add network-to-network rule with ports masks set(mask type xx or xxx.xxx.xxx.xxx allowed)\n\
      ", program_name, program_name, program_name);

    exit(status);
}
