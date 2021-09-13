# Dicos-public
Dicos is an approach for discovering insecure code snippets in Stack Overflow.
Principles and experimental results are discussed in [our paper](https://github.com/hyunji-Hong/Dicos-public/paper/), which will be published at the Annual Computer Security Applications Conference (ACSAC 2021).

※ Exception handling parts may be insufficient due to many modifications in the code refactoring process; we will improve them.

## How to use
### Requirements

#### Software
* ***Linux***: Dicos is designed to work on any of the operating systems. However, currently, this repository only focuses on the Linux environment.
* ***Git***
* ***Python 3***
* ***[Universal-ctags](https://github.com/universal-ctags/ctags)***: for function parsing.
* ***[Joern](https://github.com/joernio/joern)***: for generate code property graph. (only applied in C/C++) 
* ***[cpgqls-client](https://github.com/ShiftLeftSecurity/cpgqls-client-python)***: for communicating with an instance of a Code Property Graph server. (only applied in C/C++) 

  * How to install cpgqls-client:
    ```
    pip3 install cpgqls-client
    ```
  * How to setting Joern server:
    * Installation: refer to [Joern document](https://docs.joern.io/installation)
    * After following the installer instructions, by default, joern will be installed at `~/bin/joern`.
    * Create a sh file in `~/bin/joern/joern-cli`. (filename: `joern_running.sh`)
        ```
        ./joern --server
        ```

Our utilized versions: Python 3.9.1, and universal-ctags p5.9.20210620.0 on Ubuntu 18.04.

#### Stack Overflow Dataset
* ***[Google Bigquery](https://cloud.google.com/bigquery/public-data)***: Dicos requires post information of Stack Overflow. In the paper, Dicos uses [SOTorrent](https://console.cloud.google.com/bigquery?project=sotorrent-org&p=sotorrent-org&d=2020_12_31&page=dataset) dataset (version "2020-12-31") and obtained information using [SQL query](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/sql/).

#### Hardware
* We recommend 24 GB RAM.
##

### Running Dicos

※ If you have problems related to path information, try testing with absolute paths.

### Post Collector

#### 1. Collect StackOverflow raw dataset (src/bigquery_json)
 - Extract posts information through queries from the Bigquery, [SOTorrent](https://console.cloud.google.com/bigquery?project=sotorrent-org&p=sotorrent-org&d=2020_12_31&page=dataset)  dataset.
   * [***collecting_comments.sql***](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/sql/collecting_comments.sql): collect post comments including security-related keywords. (Output sample :[comment_Sample.json]())
   * [***collecting_allhistoryPost.sql***](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/sql/collecting_allhistoryPost.sql): collect post code snippets and post descriptions from all history of each post.(Output sample :[post_Sample.json]())
  
 - Store all result json files at "src/bigquery_json"
   - Note that the result json file name of [***collecting_comments.sql***](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/sql/collecting_comments.sql) query to begin with "comment_". (Please refer to the [sample file](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/bigquery_json))


#### 2. Collect code snippets by history (src/PostCodeSnippet_Collector.py)
 - Extract code snippets from the oldest and the latest versions of all posts.
 - Execute [PostCodeSnippet_Collector.py](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/PostCodeSnippet_Collector.py)
 ```
 python3 PostCodeSnippet_Collector.py
 ```
 - Check the outputs (description based on the default paths).
   * ***./dataset/code_raw/***: Directory for storing the latest and the oldest versions of code snippets for each post.


### Post Analyzer

#### 1. Pairing code snippets (src/Pairing_CodeSnippet.py)
 - Check the similarity of all code snippets between two versions and diffs in the order of high similarity.
 - Execute [Pairing_CodeSnippet.py](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/Pairing_CodeSnippet.py)
 ```
 python3 Pairing_CodeSnippet.py
 ```
 - Check the outputs (description based on the default paths).
   * ***./dataset/code_pairs/***: Directory for storing two paired code snippets and diff files.

#### 2. Discovering Insecure posts
 - Two ways to analyze the Control-Flow change, one of Dicos detection features.     
   - using Regex : See [2-1](#2-1.-Discovering-Insecure-posts---using-Regex-(src/Post_Analyzer.py))
   - using Joern-parser : Only applied in C/C++, See [2-2](#2-1.-Discovering-Insecure-posts---using-Joern-Parser-(src/))


#### 2-1. Discovering Insecure posts - using Regex (src/Post_Analyzer.py)
 - Execute [Post_Analyzer.py](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/Post_Analyzer.py).
 ```
 python3 Post_Analyzer.py
 ```


#### 2-2. Discovering Insecure posts - using Joern Parser (src/Post_Analyzer_usingJoern.py)
 -  Execute [Post_Analyzer_usingJoern.py](https://github.com/hyunji-Hong/Dicos-public/blob/main/src/Post_Analyzer_usingJoern.py).
  ```
 python3 Post_Analyzer_usingJoern.py
 ```
 -  Specify the path regarding Joern to suit the users. (Please change the global variables)

#### Check the results (description based on the default paths).
   * ***./ouput/***: Directory for storing results.
   * ***./ouput/insecure_posts.txt***: List of insecure post IDs. (two or more features detected.)
   * ***./ouput/Analyzing_codesnippet.json***: Result of the code snippets analysis.
   * ***./ouput/Analyzing_keyword.json***: Result of the post descriptions and comments analysis.
  
### About
This repository is authored and maintained by Hyunji Hong.
For reporting bugs, you can submit an issue to [the GitHub repository](https://github.com/hyunji-Hong/Dicos-public/) or send me an email (<hyunji_hong@korea.ac.kr>).
