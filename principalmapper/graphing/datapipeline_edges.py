"""Code to identify if a principal in an AWS account can use access to AWS Data Pipeline to access other principals."""


#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

import logging
from typing import Dict, List, Optional

from botocore.exceptions import ClientError

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.util import arns, botocore_tools

logger = logging.getLogger(__name__)


class DataPipelineEdgeChecker(EdgeChecker):
    """Class for identifying if Data Pipeline can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None, partition: str = 'aws') -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on Data Pipeline.')

        result = generate_edges_locally(nodes, scps)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """For Data Pipeline, we do something a little different. The way people can use DataPipeline to pivot is
    to create a pipeline, then put a definition on the pipeline that creates an EC2 instance resource. The
    role that's used by the EC2 instance is the ultimate target. This requires:

    * datapipeline:CreatePipeline (resource "*")
    * datapipeline:PutPipelineDefinition (resource "*")
    * iam:PassRole for the Data Pipeline Role (which must trust datapipeline.amazonaws.com)
    * (TODO: Verify) iam:PassRole for the EC2 Data Pipeline Role (which must trust ec2.amazonaws.com and have an instance profile)

    Note that we have two roles involved. Data Pipeline Role, which seems to be a sorta service role but
    doesn't have the same path/naming convention as other service roles, is used to actually call EC2 and
    spin up the target instance. It's meant to be accessible to datapipeline.amazonaws.com. Then, we have
    the EC2 Data Pipeline Role, which actually is accessible to the EC2 instance doing the computational
    work of the pipeline.

    Other works seemed to indicate the Data Pipeline Role was accessible, however that might not be true
    anymore? In any case, recent experimentation only allowed me access to the EC2 Data Pipeline Role.

    To create the list of edges, we gather our:

    * Potential Data Pipeline Roles
    * Potential EC2 Data Pipeline Roles

    Then we determine which of the EC2 roles are accessible to the Data Pipeline Roles, then run through all
    potential source nodes to see if they have the correct datapipeline:* + iam:PassRole permissions, then generate
    edges that have the EC2 roles as destinations.

    This vector is neat because even if specific EC2-accessible roles are blocked via ec2:RunInstances, this might be
    an alternative option the same as autoscaling was.
    """

    results = []

    return results
