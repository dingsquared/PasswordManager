#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

#include "hash.h"


/* #define  NDEBUG	*/

#define MAX_LENGTH	32
#define N_CHARS		96	/* 128 - ' ' */


double get_markov_guess_number( char *passwd, unsigned int pwdlen, char *crack_file )
{
	char	szBuf[2048];
	int		nGrams, i, j, NChars, xRow, iFoundNonZero, NModReduce, nLengths, xState;
    double	dTemp, *pdStart, *pdPrefix, (*padState)[N_CHARS], *pdLengths, dTotalStart = 0, dTotalLength = 0, dNGuesses = 0;
	FILE	*fp;


	/*
	if ( argc < 4 )
	{
		printf( "usage: %s nGrams FileToCrack TrainFile1 [TrainFile2 ...]\nIf 'nGrams' is < 0, the program will actually try to guess to the passwords in the cracking file.\nOtherwise, guess numbers are calculated for each password.", __func__ );
		return 0;
	}
	*/

	nGrams = 1;   // Set to one

	pdLengths = malloc(sizeof(pdLengths[0]) * (1 + MAX_LENGTH));
	if ( pdLengths == NULL )
	{
		fprintf( stderr, "%s - can't malloc space for pdLengths!\n", __func__ );
		return 0;
	}

	NChars = (int)pow((double)N_CHARS, (double)nGrams);
	NModReduce = NChars / N_CHARS;

	pdStart = malloc(sizeof(pdStart[0]) * NChars);
	if ( pdStart == NULL )
	{
		fprintf( stderr, "%s - can't malloc space for pdStart!\n", __func__ );
		free(pdLengths);
		return 0;
	}

	pdPrefix = malloc(sizeof(pdPrefix[0]) * NChars);
	if ( pdPrefix == NULL )
	{
		fprintf( stderr, "%s - can't malloc space for pdPrefix!\n", __func__ );
		free(pdLengths);
		free(pdStart);
		return 0;
	}

	padState = malloc(sizeof(padState[0]) * NChars);
	if ( padState == NULL )
	{
		fprintf( stderr, "%s - can't malloc space for padState!\n", __func__ );
		free(pdLengths);
		free(pdStart);
		free(pdPrefix);
		return 0;
	}

	for ( i = 0; i <= MAX_LENGTH; ++i )
	{
		pdLengths[i] = 0;
	}

	for ( i = 0; i < NChars; ++i )
	{
		pdStart[i] = 0.0;
		pdPrefix[i] = 0.0;

		for ( j = 0; j < N_CHARS; ++j )
		{
			padState[i][j] = 0.0;
		}
	}

	// open one crack file
	fp = fopen(crack_file, "r");   
	if ( fp == NULL )
	  {
	    fprintf( stderr, "%s - can't open %s for reading\n", __func__, crack_file);
	  }

        fgets(szBuf, sizeof(szBuf), fp);		/* list of chars */
 
        for ( xRow = 0; xRow < NChars; ++xRow )
        {
            fgets(szBuf, sizeof(szBuf), fp);
            for ( xState = -2, i = nGrams; xState < N_CHARS; ++xState )
            {
                assert(szBuf[i] == ' ');
                sscanf( szBuf+i, "%lf", &dTemp );

                if ( xState == -2 )
                {
                    dTemp += 1.0 / NChars;						/* add fraction so no row has a 0 probability of being chosen */
                    pdStart[xRow] += dTemp;
                    dTotalStart += dTemp;
                }
                else if ( xState == -1 )
                {
                    pdPrefix[xRow] += dTemp + N_CHARS/100.0;	/* add fraction for each possible transition state */
                }
                else
                {
                    padState[xRow][xState] += dTemp + 0.01;		/* add fraction so no state has a 0 probability of being chosen */
                }
 
                for ( ; szBuf[i] == ' '; ++i )
                {
                }

				for ( ; szBuf[i] > ' '; ++i )
                {
                }
            }

			assert(szBuf[i] == '\n');
        }
 
        fgets(szBuf, sizeof(szBuf), fp); /* length count */
        sscanf(szBuf, "%d", &nLengths);
        if ( nLengths > MAX_LENGTH )
        {
            fprintf( stderr, "%s - MAX_LENGTH not long enough for %s!!", __func__, crack_file);
            exit(0);
        }
      
        fgets(szBuf, sizeof(szBuf), fp); /* read lengths into szBuf */
        for ( iFoundNonZero = 0, i = 0, xRow = 1; xRow <= nLengths; ++xRow )
        {
            assert(szBuf[i] == ' ');
 
            sscanf(szBuf+i, "%lf", &dTemp);
            if ( !iFoundNonZero ) iFoundNonZero = dTemp > 0.0;
            if ( iFoundNonZero ) ++dTemp;   /* add 1 so no length has a 0 probability of being chosen */
            pdLengths[xRow] += dTemp;
            dTotalLength += dTemp;
 
            for ( ; szBuf[i] == ' '; ++i )
            {
            }
 
            for ( ; szBuf[i] > ' '; ++i )
            {
            }
        }
 
        assert(szBuf[i] == '\n');
	fclose(fp);

	/* Turn the counts into probabilities */
 
	for ( i = 0; i < NChars; ++i )
	  {
	    pdStart[i] /= dTotalStart;
	    
	    for ( j = 0; j < N_CHARS; ++j )
	      {
		padState[i][j] /= pdPrefix[i];
	      }
	  }
 
	for ( i = 0; i <= nLengths; ++i )
	  {
	    pdLengths[i] /= dTotalLength;
	  }

	/* Now process the cracking file against the passwd to compute guess number */

	if (( passwd != NULL ) && ( pwdlen > 0 ))
	  {
	    dNGuesses = 1e-9;                   /* measure in billions */
	    dNGuesses /= pdLengths[pwdlen];	/* probability of choosing this length */
	/*printf("p(len) = %lf\n", pdLengths[nLengths]);*/
 
	    for ( xRow = i = 0; i < nGrams; ++i )
	      {
		xRow *= N_CHARS;
		xRow += passwd[i] - ' ';
	      }
 
	    dNGuesses /= pdStart[xRow];	 /* probability of choosing this starting nGram */
	/*printf("p(start) = %lf\n", pdStart[xRow]);*/
 
	    for ( ; i < pwdlen ; ++i )
	      {
		dNGuesses /= padState[xRow][passwd[i] - ' '];    /* Probability of choosing this next state */
		/*printf("p(trans) = %lf\n", padState[xRow][szBuf[i] - ' ']);*/
		xRow %= NModReduce;			/* throw out first char in old nGram */
		xRow *= N_CHARS;			/* and calculate the new nGram */
		xRow += passwd[i] - ' ';
	      }
 
	    printf( "%9.3lf\t%s\n", dNGuesses, passwd );  // return dNGuesses 
	  }

	/* Clean up, go home */

	free(pdLengths);
	free(padState);
	free(pdStart);
	free(pdPrefix);

	return dNGuesses;

}
